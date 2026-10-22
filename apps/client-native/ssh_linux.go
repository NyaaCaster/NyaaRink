package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
)

type daemonProcess struct{}

func removeLocalSecrets(_ string) error { return nil }

func (p *daemonProcess) stop() {}
func localCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, e := cmd.Output()
	return strings.TrimSpace(string(out)), e
}
func prepareLocal(_, _ string, previous *Enrollment) (*Enrollment, string, error) {
	if _, e := os.Stat("/usr/sbin/sshd"); os.IsNotExist(e) {
		if !confirm("将使用 apt 安装并启动 OpenSSH Server，需要本地 sudo；不授予 root SSH 权限。是否继续？") {
			return nil, "", errors.New("SSH preparation cancelled; authorization retained")
		}
		cmd := exec.Command("sudo", "--", "/bin/sh", "-c", "set -eu; apt-get update; apt-get install -y openssh-server; systemctl enable --now ssh")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if e = cmd.Run(); e != nil {
			return nil, "", e
		}
	}
	status, e := localCommand("systemctl", "is-active", "ssh")
	if e != nil || status != "active" {
		if !confirm("将通过本地 sudo 启动并启用 ssh 服务，不覆盖配置，是否继续？") {
			return nil, "", errors.New("SSH startup cancelled")
		}
		cmd := exec.Command("sudo", "--", "systemctl", "enable", "--now", "ssh")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if e = cmd.Run(); e != nil {
			return nil, "", e
		}
	}
	unit, e := localCommand("systemctl", "show", "ssh.service", "--property=ExecStart,Environment,EnvironmentFiles,MainPID")
	if e != nil {
		return nil, "", e
	}
	props := map[string]string{}
	for _, line := range strings.Split(unit, "\n") {
		a, b, ok := strings.Cut(line, "=")
		if ok {
			props[a] = b
		}
	}
	valid := regexp.MustCompile(`^\{ path=/usr/sbin/sshd ; argv\[\]=/usr/sbin/sshd -D(?: \$SSHD_OPTS)? ;[^{}]*\}$`)
	if !valid.MatchString(props["ExecStart"]) || (props["Environment"] != "" && props["Environment"] != "SSHD_OPTS=" && props["Environment"] != `"SSHD_OPTS="`) || (props["EnvironmentFiles"] != "" && props["EnvironmentFiles"] != "/etc/default/ssh (ignore_errors=yes)") {
		return nil, "", errors.New("custom SSH service unsupported; configuration unchanged")
	}
	if defaults, e := os.ReadFile("/etc/default/ssh"); e == nil {
		allowed := regexp.MustCompile(`^SSHD_OPTS=(?:|''|"")(?:\s+#.*)?$`)
		for _, line := range strings.Split(string(defaults), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && !allowed.MatchString(line) {
				return nil, "", errors.New("custom SSH startup options unsupported")
			}
		}
	}
	pid := props["MainPID"]
	if !regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(pid) {
		return nil, "", errors.New("invalid SSH process")
	}
	executable, e := os.Readlink("/proc/" + pid + "/exe")
	if e != nil {
		if !confirm("需要 sudo 只读核验运行中 sshd 程序，不改变服务与账户，是否继续？") {
			return nil, "", e
		}
		cmd := exec.Command("sudo", "--", "/usr/bin/readlink", "-e", "/proc/"+pid+"/exe")
		cmd.Stdin = os.Stdin
		out, e := cmd.Output()
		if e != nil {
			return nil, "", e
		}
		executable = strings.TrimSpace(string(out))
	}
	now, e := localCommand("systemctl", "show", "ssh.service", "--property=MainPID", "--value")
	if e != nil || now != pid || executable != "/usr/sbin/sshd" {
		return nil, "", errors.New("SSH process identity changed")
	}
	who, e := user.Current()
	if e != nil {
		return nil, "", e
	}
	port := 22
	if previous != nil {
		port = previous.Port
	} else {
		input := ask("本机 SSH 端口 [22]：")
		if input != "" {
			if _, e = fmt.Sscan(input, &port); e != nil {
				return nil, "", e
			}
		}
	}
	if port < 1 || port > 65535 {
		return nil, "", errors.New("invalid SSH port")
	}
	args := []string{"-T", "-C", fmt.Sprintf("user=%s,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=%d", who.Username, port)}
	text, e := localCommand("/usr/sbin/sshd", args...)
	if e != nil {
		if !confirm("需要 sudo 只读检查有效 SSH 配置，不上传私钥，是否继续？") {
			return nil, "", e
		}
		cmd := exec.Command("sudo", append([]string{"--", "/usr/sbin/sshd"}, args...)...)
		cmd.Stdin = os.Stdin
		out, e := cmd.Output()
		if e != nil {
			return nil, "", e
		}
		text = string(out)
	}
	options := map[string]string{}
	keys := []string{}
	for _, line := range strings.Split(text, "\n") {
		name, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		options[name] = value
		if name == "hostkey" {
			pub, e := os.ReadFile(value + ".pub")
			if e != nil {
				continue
			}
			parsed, _, _, _, e := ssh.ParseAuthorizedKey(pub)
			if e != nil {
				return nil, "", e
			}
			keys = append(keys, base64.StdEncoding.EncodeToString(parsed.Marshal()))
		}
	}
	algorithms := options["pubkeyacceptedalgorithms"]
	if algorithms == "" {
		algorithms = options["pubkeyacceptedkeytypes"]
	}
	if options["pubkeyauthentication"] != "yes" || options["authorizedkeyscommand"] != "none" || options["permittty"] != "yes" || !strings.Contains(","+algorithms+",", ",ssh-ed25519,") || !strings.Contains(text, "subsystem sftp ") || !strings.Contains("\n"+text, "\nport "+fmt.Sprint(port)+"\n") || len(keys) == 0 {
		return nil, "", errors.New("SSH authentication, PTY, SFTP or host identity unsupported")
	}
	paths := strings.Fields(options["authorizedkeysfile"])
	if len(paths) == 0 || paths[0] == "none" {
		return nil, "", errors.New("no authorized_keys path")
	}
	path := strings.NewReplacer("%h", who.HomeDir, "%u", who.Username, "%%", "%").Replace(paths[0])
	if strings.Contains(path, "%") {
		return nil, "", errors.New("unsupported SSH path expansion")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(who.HomeDir, path)
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, "", e
	}
	if _, e = os.Lstat(path); os.IsNotExist(e) {
		if e = durableWrite(path, []byte{}); e != nil {
			return nil, "", e
		}
	}
	return &Enrollment{Account: who.Username, Home: who.HomeDir, Shell: "posix", Platform: "linux", Host: "127.0.0.1", Port: port, HostKeys: keys}, path, nil
}
func startLocal(_ string, s *State) (*daemonProcess, error) {
	who, err := user.Current()
	if err != nil {
		return nil, err
	}
	if s.Enrollment == nil || who.Username != s.Enrollment.Account || who.HomeDir != s.Enrollment.Home {
		return nil, errors.New("SSH account binding changed")
	}
	return &daemonProcess{}, probeHost(s.Enrollment)
}
