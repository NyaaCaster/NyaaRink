package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"strings"
	"time"
)

func probeHost(local *Enrollment) error {
	if local.Host != "127.0.0.1" && local.Host != "::1" {
		return errors.New("non-loopback target refused")
	}
	matched := false
	cfg := &ssh.ClientConfig{User: local.Account, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		raw := base64.StdEncoding.EncodeToString(key.Marshal())
		for _, allowed := range local.HostKeys {
			if raw == allowed {
				matched = true
				return nil
			}
		}
		return errors.New("SSH host identity mismatch")
	}, Timeout: 2 * time.Second}
	conn, e := net.DialTimeout("tcp", net.JoinHostPort(local.Host, fmt.Sprint(local.Port)), 2*time.Second)
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	c, _, _, e := ssh.NewClientConn(conn, "loopback", cfg)
	if c != nil {
		c.Close()
	}
	if matched && e != nil && strings.Contains(e.Error(), "unable to authenticate") {
		return nil
	}
	if e == nil && matched {
		return nil
	}
	return errors.New("SSH host identity/authentication check failed")
}
func changeKey(path, id, key string, add bool) error {
	if !uuidPattern.MatchString(id) {
		return errors.New("invalid key session")
	}
	if e := privatePath(path); e != nil {
		return e
	}
	unlock, e := platformLock(path + ".nyaarink-native.lock")
	if e != nil {
		return e
	}
	defer unlock()
	data, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(data) > 1024*1024 {
		return errors.New("authorized_keys too large")
	}
	marker := " nyaarink:" + id
	pub, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(key))
	if e != nil || len(bytes.TrimSpace(rest)) != 0 || pub.Type() != ssh.KeyAlgoED25519 {
		return errors.New("invalid SSH authorization key")
	}
	line := `from="127.0.0.1,::1",restrict,pty ` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + marker
	original := string(data)
	contains := false
	var content strings.Builder
	for _, part := range strings.SplitAfter(original, "\n") {
		text := strings.TrimSuffix(strings.TrimSuffix(part, "\n"), "\r")
		if text == line {
			contains = true
			if !add {
				continue
			}
		}
		if add && strings.Contains(text, marker) && text != line {
			return errors.New("conflicting session key marker")
		}
		content.WriteString(part)
	}
	if add && !contains {
		if content.Len() > 0 && !strings.HasSuffix(original, "\n") {
			content.WriteString("\n")
		}
		content.WriteString(line + "\n")
	}
	if (!add && !contains) || (add && contains) {
		return nil
	}
	return replaceAuthorized(path, []byte(content.String()))
}
