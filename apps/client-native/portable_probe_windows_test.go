package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

type probeLog struct {
	sync.Mutex
	bytes.Buffer
}

func (b *probeLog) Write(p []byte) (int, error) { b.Lock(); defer b.Unlock(); return b.Buffer.Write(p) }
func (b *probeLog) text() string                { b.Lock(); defer b.Unlock(); return b.Buffer.String() }

// Opt-in, isolated loopback capability probe. Nyaa be with you.
func TestPortableChild(t *testing.T) {
	if os.Getenv("NYAARINK_PROBE_CHILD") != "1" {
		t.Skip("explicit probe only")
	}
	token := windows.GetCurrentProcessToken()
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	member, err := token.IsMember(admin)
	if err != nil {
		t.Fatal(err)
	}
	if member {
		t.Fatal("probe token still has enabled administrators group")
	}
	who, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("restricted token; elevated=%v; not an independent ordinary-account acceptance", token.IsElevated())
	root := t.TempDir()
	protect := func(path string) {
		sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + who.Uid + ")(A;OICI;FA;;;SY)")
		if e != nil {
			t.Fatal(e)
		}
		acl, _, e := sd.DACL()
		if e != nil {
			t.Fatal(e)
		}
		if e = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); e != nil {
			t.Fatal(e)
		}
	}
	protect(root)
	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(hostPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	hostFile := filepath.Join(root, "host")
	if err = os.WriteFile(hostFile, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	protect(hostFile)
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(root, "authorized_keys")
	if err = os.WriteFile(keys, append([]byte("from=\"127.0.0.1,::1\",restrict,pty "), ssh.MarshalAuthorizedKey(signer.PublicKey())...), 0600); err != nil {
		t.Fatal(err)
	}
	protect(keys)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	dir := os.Getenv("NYAARINK_PORTABLE_SSH")
	if dir == "" {
		t.Fatal("official OpenSSH directory required")
	}
	quote := func(s string) string { return "\"" + filepath.ToSlash(s) + "\"" }
	config := filepath.Join(root, "sshd_config")
	body := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nAuthorizedKeysFile %s\nPubkeyAuthentication yes\nPasswordAuthentication no\nPermitTTY yes\nStrictModes yes\nSubsystem sftp %s\n", port, quote(hostFile), quote(keys), quote(filepath.Join(dir, "sftp-server.exe")))
	if err = os.WriteFile(config, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	var logs probeLog
	daemon := exec.Command(filepath.Join(dir, "sshd.exe"), "-D", "-e", "-f", config)
	daemon.Stderr = &logs
	if err = daemon.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { daemon.Process.Kill(); daemon.Wait(); t.Log(logs.text()) }()
	hostKey, err := ssh.NewPublicKey(hostPub)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ClientConfig{User: who.Username, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: 2 * time.Second}
	dial := func() (*ssh.Client, error) { return ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg) }
	var c *ssh.Client
	for i := 0; i < 20; i++ {
		c, err = dial()
		if err == nil {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("authentication failed: %v; daemon: %s", err, logs.text())
	}
	defer c.Close()
	for _, pty := range []bool{false, true} {
		s, e := c.NewSession()
		if e != nil {
			t.Fatal(e)
		}
		if pty {
			if e = s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); e != nil {
				t.Fatal(e)
			}
		}
		out, e := s.CombinedOutput("cmd.exe /d /c echo NYAARINK_COMPAT_OK")
		s.Close()
		if e != nil || !strings.Contains(string(out), "NYAARINK_COMPAT_OK") {
			t.Fatalf("exec pty=%v: %v %s", pty, e, out)
		}
	}
	second, e := dial()
	if e != nil {
		t.Fatal("second simultaneous authentication", e)
	}
	second.Close()
	c.Close()
	third, e := dial()
	if e != nil {
		t.Fatal("subsequent authentication", e)
	}
	third.Close()
	t.Log("authentication, exec, PTY and simultaneous/subsequent connections passed under restricted token")
}
