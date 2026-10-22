package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Explicit isolated probe of the actual product configuration and minimal DLL set.
func TestNativePortable(t *testing.T) {
	source := os.Getenv("NYAARINK_PORTABLE_SSH")
	if source == "" {
		t.Skip("explicit official archive probe only")
	}
	runtime := t.TempDir()
	for _, name := range []string{"sshd.exe", "sshd-auth.exe", "sshd-session.exe", "ssh-shellhost.exe", "sftp-server.exe", "libcrypto.dll"} {
		data, e := os.ReadFile(filepath.Join(source, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(runtime, name), data, 0700); e != nil {
			t.Fatal(e)
		}
		if e = verifyMicrosoft(filepath.Join(runtime, name)); e != nil {
			t.Fatalf("%s: %v", name, e)
		}
	}
	dir := t.TempDir()
	if e := privatePath(dir); e != nil {
		t.Fatal(e)
	}
	local, keys, e := prepareLocal(dir, runtime, nil)
	if e != nil {
		t.Fatal(e)
	}
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(private)
	if e != nil {
		t.Fatal(e)
	}
	id := randomID()
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if e = changeKey(keys, id, key, true); e != nil {
		t.Fatal(e)
	}
	state := &State{Runtime: runtime, Enrollment: local}
	daemon, e := startLocal(dir, state)
	if e != nil {
		t.Fatal(e)
	}
	defer daemon.stop()
	var cfg *ssh.ClientConfig

	hostBytes, e := os.ReadFile(filepath.Join(dir, "host_ed25519"))
	if e != nil {
		t.Fatal(e)
	}
	host, e := ssh.ParsePrivateKey(hostBytes)
	if e != nil {
		t.Fatal(e)
	}
	cfg = &ssh.ClientConfig{User: local.Account, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: 5 * time.Second}
	address := fmt.Sprintf("127.0.0.1:%d", local.Port)
	client, e := ssh.Dial("tcp", address, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	for _, pty := range []bool{false, true} {
		session, e := client.NewSession()
		if e != nil {
			t.Fatal(e)
		}
		if pty {
			if e = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); e != nil {
				t.Fatal(e)
			}
		}
		output, e := session.CombinedOutput("cmd.exe /d /c echo NYAARINK_NATIVE_OK")
		session.Close()
		if e != nil || !strings.Contains(string(output), "NYAARINK_NATIVE_OK") {
			t.Fatalf("exec pty=%v: %v %s", pty, e, output)
		}
	}
	channel, requests, e := client.OpenChannel("session", nil)
	if e != nil {
		t.Fatal(e)
	}
	go ssh.DiscardRequests(requests)
	if ok, e := channel.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"})); e != nil || !ok {
		t.Fatal("SFTP subsystem", e)
	}
	channel.Close()
	if conn, e := client.Dial("tcp", address); e == nil {
		conn.Close()
		t.Fatal("forwarding unexpectedly accepted")
	}
	if e = changeKey(keys, id, key, false); e != nil {
		t.Fatal(e)
	}
	if extra, e := ssh.Dial("tcp", address, cfg); e == nil {
		extra.Close()
		t.Fatal("removed key accepted")
	}
	// A long-running command must die with the portable server's job tree.
	long, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	stdout, e := long.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = long.Start(`powershell.exe -NoProfile -Command "[Console]::WriteLine($PID); Start-Sleep -Seconds 120"`); e != nil {
		t.Fatal(e)
	}
	line, e := bufio.NewReader(stdout).ReadString('\n')
	if e != nil {
		t.Fatal(e)
	}
	pid, e := strconv.ParseUint(strings.TrimSpace(line), 10, 32)
	if e != nil {
		t.Fatal(e)
	}
	handle, e := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(handle)
	daemon.stop()
	if status, e := windows.WaitForSingleObject(handle, 5000); e != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatal("SSH command survived daemon stop", status, e)
	}
	long.Close()
	t.Log("minimal official components: signature, real product config, exec, PTY, SFTP, forwarding denial, key removal passed")
}
