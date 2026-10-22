package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
	"unsafe"
)

func portablePaths(dir string) (string, string, string) {
	return filepath.Join(dir, "sshd_config"), filepath.Join(dir, "host_ed25519"), filepath.Join(dir, "authorized_keys")
}
func prepareLocal(dir, runtime string, previous *Enrollment) (*Enrollment, string, error) {
	who, e := user.Current()
	if e != nil {
		return nil, "", e
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return nil, "", e
	}
	for _, name := range []string{"sshd.exe", "sshd-auth.exe", "sshd-session.exe", "ssh-shellhost.exe", "sftp-server.exe", "libcrypto.dll"} {
		if e = verifyMicrosoft(filepath.Join(runtime, name)); e != nil {
			return nil, "", fmt.Errorf("%s: %w", name, e)
		}
	}
	config, host, keys := portablePaths(dir)
	if _, e = os.Lstat(host); os.IsNotExist(e) {
		_, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, "", e
		}
		block, e := ssh.MarshalPrivateKey(private, "")
		if e != nil {
			return nil, "", e
		}
		if e = durableWrite(host, pem.EncodeToMemory(block)); e != nil {
			return nil, "", e
		}
	}
	contents, e := os.ReadFile(host)
	if e != nil {
		return nil, "", e
	}
	signer, e := ssh.ParsePrivateKey(contents)
	if e != nil {
		return nil, "", e
	}
	port := 0
	if previous != nil {
		port = previous.Port
	} else {
		socket, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return nil, "", e
		}
		port = socket.Addr().(*net.TCPAddr).Port
		socket.Close()
	}
	quote := func(path string) string { return "\"" + filepath.ToSlash(path) + "\"" }
	// Explicit AllowUsers and loopback binding prevent cross-account or LAN use.
	account := strings.ToLower(who.Username)
	computer, e := os.Hostname()
	if e != nil {
		return nil, "", e
	}
	if domain, name, found := strings.Cut(account, `\`); found && strings.EqualFold(domain, computer) {
		account = name
	}
	if strings.ContainsAny(account, "\r\n\"*?[]! ") {
		return nil, "", errors.New("unsupported Windows account name")
	}
	body := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s\nAllowUsers %s\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\nPermitTTY yes\nStrictModes yes\nAllowTcpForwarding no\nAllowAgentForwarding no\nAllowStreamLocalForwarding no\nGatewayPorts no\nPermitTunnel no\nX11Forwarding no\nSubsystem sftp %s\n", port, quote(host), quote(filepath.Join(dir, "sshd.pid")), quote(keys), account, quote(filepath.Join(runtime, "sftp-server.exe")))
	if e = durableWrite(config, []byte(body)); e != nil {
		return nil, "", e
	}
	if _, e = os.Lstat(keys); os.IsNotExist(e) {
		if e = durableWrite(keys, []byte{}); e != nil {
			return nil, "", e
		}
	}
	return &Enrollment{Account: account, Home: home, Shell: "cmd", Platform: "win32", Host: "127.0.0.1", Port: port, HostKeys: []string{base64.StdEncoding.EncodeToString(signer.PublicKey().Marshal())}}, keys, nil
}

type daemonProcess struct {
	cmd  *exec.Cmd
	done chan error
	once sync.Once
	job  windows.Handle
}

func startLocal(dir string, s *State) (*daemonProcess, error) {
	if s.Enrollment == nil || s.Enrollment.Host != "127.0.0.1" {
		return nil, errors.New("invalid portable SSH target")
	}
	local, keys, e := prepareLocal(dir, s.Runtime, s.Enrollment)
	if e != nil {
		return nil, e
	}
	local.SessionID = s.Enrollment.SessionID
	local.EnrollmentID = s.Enrollment.EnrollmentID
	local.DevicePublicKey = s.Enrollment.DevicePublicKey
	if !reflect.DeepEqual(local, s.Enrollment) || (s.AuthorizedKeys != "" && s.AuthorizedKeys != keys) {
		return nil, errors.New("portable SSH account or host binding changed")
	}
	config, _, _ := portablePaths(dir)
	cmd := exec.Command(filepath.Join(s.Runtime, "sshd.exe"), "-D", "-e", "-f", config)
	// Logging contains metadata only and is bounded by process lifetime.
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = hiddenProcess()
	// No child code runs before the whole process tree belongs to our job.
	cmd.SysProcAttr.CreationFlags = windows.CREATE_SUSPENDED
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		return nil, e
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
		windows.CloseHandle(job)
		return nil, e
	}
	if e := cmd.Start(); e != nil {
		windows.CloseHandle(job)
		return nil, e
	}
	h, e := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if e == nil {
		e = windows.AssignProcessToJobObject(job, h)
		windows.CloseHandle(h)
	}
	if e == nil {
		e = resumeInitialThread(uint32(cmd.Process.Pid))
	}
	if e != nil {
		cmd.Process.Kill()
		cmd.Wait()
		windows.CloseHandle(job)
		return nil, e
	}
	p := &daemonProcess{cmd: cmd, done: make(chan error, 1), job: job}
	go func() { p.done <- cmd.Wait() }()
	for i := 0; i < 40; i++ {
		select {
		case err := <-p.done:
			windows.CloseHandle(job)
			return nil, fmt.Errorf("portable sshd exited: %v", err)
		default:
		}
		if e := probeHost(s.Enrollment); e == nil {
			return p, nil
		}
		time.Sleep(125 * time.Millisecond)
	}
	p.stop()
	return nil, errors.New("portable SSH host identity/startup check failed")
}
func removeLocalSecrets(dir string) error {
	for _, name := range []string{"host_ed25519", "sshd_config", "sshd.pid"} {
		if e := os.Remove(filepath.Join(dir, name)); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	return nil
}
func (p *daemonProcess) stop() {
	if p != nil {
		p.once.Do(func() {
			windows.CloseHandle(p.job)
			_ = p.cmd.Process.Kill()
			select {
			case <-p.done:
			case <-time.After(5 * time.Second):
			}
		})
	}
}
