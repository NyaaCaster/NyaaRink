package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

var terminal = bufio.NewReader(os.Stdin)
var regexpBrowser = regexp.MustCompile(`^[A-Z2-7]{12}$`)

func ask(text string) string {
	if !interactive() {
		return ""
	}
	fmt.Print(text)
	line, _ := terminal.ReadString('\n')
	return strings.TrimSpace(line)
}
func confirm(text string) bool {
	if !interactive() {
		return false
	}
	return strings.EqualFold(ask(text+"\n输入 YES 或 yes 继续（其他输入取消）："), "yes")
}
func filepathJoin(parts ...string) string { return filepath.Join(parts...) }
func enroll(dir string, s *State) error {
	signature, e := deviceSignature(s, "enroll", digest([]byte(s.Bootstrap.BootstrapKey)), s.Enrollment)
	if e != nil {
		return e
	}
	var result struct {
		V            int    `json:"v"`
		InstanceID   string `json:"instanceId"`
		Epoch        string `json:"epoch"`
		SessionID    string `json:"sessionId"`
		SSHPublicKey string `json:"sshPublicKey"`
	}
	if e = (DeviceAPI{s, nil}).post("/api/v1/device/enroll", map[string]any{"data": s.Enrollment, "bootstrapKey": s.Bootstrap.BootstrapKey, "signature": signature}, &result); e != nil {
		return e
	}
	if result.V != 1 || result.InstanceID != s.Bootstrap.InstanceID || result.Epoch != s.Bootstrap.Epoch || result.SessionID != s.Bootstrap.SessionID {
		return errors.New("enrollment response identity mismatch")
	}
	s.SSHPublicKey = result.SSHPublicKey
	s.Phase = "enrolled"
	return writeState(dir, s)
}
func install(bootstrapPath string) (*State, string, error) {
	data, e := os.ReadFile(bootstrapPath)
	if e != nil {
		return nil, "", e
	}
	if len(data) > 16384 {
		return nil, "", errors.New("bootstrap too large")
	}
	var boot Bootstrap
	if e = strictJSON(data, &boot); e != nil {
		return nil, "", e
	}
	if e = boot.validate(); e != nil {
		return nil, "", e
	}
	dir, e := stateDirectory(boot.SessionID)
	if e != nil {
		return nil, "", e
	}
	unlock, e := writerLock(dir)
	if e != nil {
		return nil, "", e
	}
	defer unlock()
	exe, e := os.Executable()
	if e != nil {
		return nil, "", e
	}
	runtime, e := installRuntime(filepath.Dir(exe))
	if e != nil {
		return nil, "", e
	}
	var s *State
	if _, e = os.Lstat(filepath.Join(dir, "state.json")); e == nil {
		s, e = readState(dir)
		if e != nil {
			return nil, "", e
		}
		if s.Bootstrap.Origin != boot.Origin || s.Bootstrap.InstanceID != boot.InstanceID || s.Bootstrap.Epoch != boot.Epoch {
			return nil, "", errors.New("conflicting invitation identity")
		}
		if s.Phase == "revoked" || s.Phase == "cleaned" {
			return nil, "", errors.New("authorization permanently revoked")
		}
		if revoked(dir) {
			return nil, "", errors.New("authorization permanently revoked")
		}
		if s.Phase == "ready" {
			return s, dir, verifyRelease(s.Runtime)
		}
		if s.Bootstrap.EnrollmentID != boot.EnrollmentID {
			if s.Enrollment != nil || s.Phase != "preparing" {
				return nil, "", errors.New("cannot replace enrolled identity")
			}
			s.Bootstrap = boot
		}
	} else if !os.IsNotExist(e) {
		return nil, "", e
	} else {
		private, public, e := devicePair()
		if e != nil {
			return nil, "", e
		}
		s = &State{V: 1, Bootstrap: boot, DevicePrivateKey: private, DevicePublicKey: public, Phase: "preparing", Runtime: runtime, Cleanup: "pending", ReleaseVersion: version, Native: true}
	}
	if e = writeState(dir, s); e != nil {
		return nil, "", e
	}
	if !confirm("S端：" + boot.Origin + "\n将允许协助者（可能含 AI Agent）通过 SSH 操作当前账户；断网不撤权，登录后自动恢复。只有主动断开才撤权。确认本次连接？") {
		return nil, "", errors.New("未确认本次配置；授权保留等待")
	}
	if privilegedAccount() && !confirm("当前目标账户属于管理员/root，远程操作可能拥有高权限。建议使用普通账户。是否明确授权该账户 SSH？") {
		return nil, "", errors.New("高权限账户未获确认")
	}
	local, keys, e := prepareLocal(dir, s.Runtime, s.Enrollment)
	if e != nil {
		return nil, "", e
	}
	local.SessionID = boot.SessionID
	local.EnrollmentID = boot.EnrollmentID
	local.DevicePublicKey = s.DevicePublicKey
	if s.Enrollment != nil && !reflect.DeepEqual(s.Enrollment, local) {
		return nil, "", errors.New("本地账户或主机身份已改变；禁止自动替换绑定")
	}
	fmt.Printf("实际账户：%s；回环 SSH：%s:%d\n", local.Account, local.Host, local.Port)
	if !confirm("确认以上账户与独立连接设置？") {
		return nil, "", errors.New("账户确认取消；授权保留")
	}
	s.Enrollment = local
	s.AuthorizedKeys = keys
	if e = writeState(dir, s); e != nil {
		return nil, "", e
	}
	daemon, e := startLocal(dir, s)
	if e != nil {
		return nil, "", e
	}
	defer daemon.stop()
	if e = enroll(dir, s); e != nil {
		return nil, "", e
	}
	if revoked(dir) {
		return nil, "", errors.New("local revocation already effective")
	}
	if e = changeKey(keys, boot.SessionID, s.SSHPublicKey, true); e != nil {
		return nil, "", e
	}
	if e = installLogin(dir, s, false); e != nil {
		_ = changeKey(keys, boot.SessionID, s.SSHPublicKey, false)
		_ = removeLogin(s, false)
		return nil, "", e
	}
	s.Phase = "ready"
	if e = writeState(dir, s); e != nil {
		return nil, "", e
	}
	return s, dir, nil
}
func cleanupLocal(dir string, s *State) error {
	if s.Phase == "cleaned" {
		return nil
	}
	if e := durableWrite(filepath.Join(dir, "revoked"), []byte(`{"revoked":true}`)); e != nil {
		return e
	}
	s.Phase = "revoked"
	s.Cleanup = "pending"
	if e := writeState(dir, s); e != nil {
		return e
	}
	failed := false
	if e := installLogin(dir, s, true); e != nil {
		failed = true
	}
	if s.AuthorizedKeys != "" && s.SSHPublicKey != "" {
		if e := changeKey(s.AuthorizedKeys, s.Bootstrap.SessionID, s.SSHPublicKey, false); e != nil {
			failed = true
		}
	}
	if e := removeLocalSecrets(dir); e != nil {
		failed = true
	}
	if e := removeLogin(s, false); e != nil {
		failed = true
	}
	if failed {
		s.Cleanup = "failed"
	}
	if e := writeState(dir, s); e != nil {
		return e
	}
	api := DeviceAPI{s, nil}
	if e := api.perform("disconnect", nil, nil); e != nil {
		return e
	}
	s.Reported = true
	if e := writeState(dir, s); e != nil {
		return e
	}
	if !failed {
		if e := removeLogin(s, true); e != nil {
			failed = true
		}
	}
	outcome := "confirmed"
	if failed {
		outcome = "failed"
	}
	if e := api.perform("cleanup-ack", map[string]any{"result": outcome}, nil); e != nil {
		_ = installLogin(dir, s, true)
		return e
	}
	s.Cleanup = outcome
	if !failed {
		s.DevicePrivateKey = ""
		s.SSHPublicKey = ""
		s.Bootstrap.BootstrapKey = strings.Repeat("0", 43)
		s.Phase = "cleaned"
	}
	return writeState(dir, s)
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		fmt.Fprintln(os.Stderr, "操作未完成；网络或安装失败不会自动撤销授权。")
		os.Exit(1)
	}
}
func run() error {
	fmt.Println("NyaaRink | Nyaa be with you.")
	if len(os.Args) < 2 {
		return errors.New("usage: install|resume|status|disconnect|cleanup|resume-browser|verify|--version")
	}
	command := os.Args[1]
	if command == "--version" {
		fmt.Println(version)
		return nil
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	bootstrap := flags.String("bootstrap", "", "bootstrap path")
	session := flags.String("session", "", "session UUID")
	directory := flags.String("directory", "", "release directory")
	code := flags.String("code", "", "browser recovery code")
	if e := flags.Parse(os.Args[2:]); e != nil {
		return e
	}
	if command == "verify" {
		return verifyRelease(*directory)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if command == "install" {
		s, dir, e := install(*bootstrap)
		if e != nil {
			return e
		}
		unlock, e := writerLock(dir)
		if e != nil {
			return e
		}
		defer unlock()
		return runTunnel(ctx, dir, s)
	}
	dir, e := stateDirectory(*session)
	if e != nil {
		return e
	}
	s, e := readState(dir)
	if e != nil {
		return e
	}
	if command == "status" {
		out, _ := json.MarshalIndent(map[string]any{"sessionId": s.Bootstrap.SessionID, "phase": s.Phase, "cleanup": s.Cleanup, "reported": s.Reported, "origin": s.Bootstrap.Origin}, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	if command == "disconnect" {
		if !confirm("将永久撤销本次 SSH 访问并终止操作。网络断开无需执行此命令。确认主动断开？") {
			return nil
		}
		if e = durableWrite(filepath.Join(dir, "revoked"), []byte(`{"revoked":true}`)); e != nil {
			return e
		}
	}
	unlock, e := writerLock(dir)
	if command == "disconnect" && e != nil {
		for attempt := 0; attempt < 60 && e != nil; attempt++ {
			time.Sleep(250 * time.Millisecond)
			unlock, e = writerLock(dir)
		}
	}
	if e != nil {
		return e
	}
	defer unlock()
	s, e = readState(dir)
	if e != nil {
		return e
	}
	switch command {
	case "disconnect", "cleanup", "resume":
		if s.Phase == "cleaned" {
			return nil
		}
		if revoked(dir) || s.Phase == "revoked" {
			return cleanupLocal(dir, s)
		}
		if command != "resume" {
			return errors.New("有效授权不能作为垃圾清理，请显式 disconnect")
		}
		if s.Phase != "ready" {
			return errors.New("本地准备未完成，请重新运行连接包")
		}
		return runTunnel(ctx, dir, s)
	case "resume-browser":
		if s.Phase != "ready" || !regexpBrowser.MatchString(*code) {
			return errors.New("需要有效会话和 12 位恢复码")
		}
		if !confirm("将页面绑定至配对码 " + *code + " 对应浏览器，确认？") {
			return nil
		}
		return (DeviceAPI{s, nil}).perform("recover-browser", map[string]any{"code": *code}, nil)
	default:
		return errors.New("unknown command")
	}
}
