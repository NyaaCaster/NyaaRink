package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeServer(t *testing.T) {
	input := os.Getenv("NYAARINK_GO_FIXTURE")
	if input == "" {
		t.Skip("explicit disposable S fixture required")
	}
	var f struct {
		Bootstrap                         Bootstrap
		Cert, Runtime, Root, Secret, Mode string
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(f.Cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("test CA invalid")
	}
	private, public, err := devicePair()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.Root, f.Bootstrap.SessionID)
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = privatePath(dir); err != nil {
		t.Fatal(err)
	}
	s := &State{V: 1, Native: true, Bootstrap: f.Bootstrap, DevicePrivateKey: private, DevicePublicKey: public, Runtime: f.Runtime, Phase: "preparing", Cleanup: "pending", ReleaseVersion: version, tlsConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	if err = verifyRelease(f.Runtime); err != nil {
		t.Fatal(err)
	}
	local, keys, err := prepareLocal(dir, s.Runtime, nil)
	if err != nil {
		t.Fatal(err)
	}
	local.SessionID = s.Bootstrap.SessionID
	local.EnrollmentID = s.Bootstrap.EnrollmentID
	local.DevicePublicKey = public
	s.Enrollment = local
	s.AuthorizedKeys = keys
	if err = enroll(dir, s); err != nil {
		t.Fatal("real TS enroll signature:", err)
	}
	if err = changeKey(keys, s.Bootstrap.SessionID, s.SSHPublicKey, true); err != nil {
		t.Fatal(err)
	}
	s.Phase = "ready"
	if err = writeState(dir, s); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = removeLogin(s, false); _ = removeLogin(s, true) }()
	// A tiny authenticated test endpoint drives the real S hub, never production.
	action := func(name string) map[string]any {
		t.Helper()
		client := DeviceAPI{s, nil}
		result, e := fixturePost(client, f.Secret, name, filepath.Join(f.Root, "sftp-roundtrip.txt"))
		if e != nil {
			t.Fatal(name, e)
		}
		return result
	}
	waitOnline := func() {
		t.Helper()
		end := time.Now().Add(20 * time.Second)
		for time.Now().Before(end) {
			if action("online")["online"] == true {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("native tunnel did not become verified")
	}
	daemon, err := startLocal(dir, s)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controlSession(ctx, dir, s) }()
	waitOnline()
	action("exercise")
	action("cut")
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("network cancellation stuck")
	}
	if revoked(dir) || action("online")["authorization"] != "enrolled" {
		t.Fatal("network loss revoked authorization")
	}
	persisted, err := readState(dir)
	if err != nil || persisted.Phase != "ready" || persisted.DevicePrivateKey == "" {
		t.Fatal("network loss destroyed local identity", err)
	}
	go func() { done <- controlSession(ctx, dir, s) }()
	waitOnline()
	action("exercise")
	if f.Mode == "local" {
		// Same durable marker used by the explicitly confirmed local disconnect command.
		if err = durableWrite(filepath.Join(dir, "revoked"), []byte(`{"revoked":true}`)); err != nil {
			t.Fatal(err)
		}
	} else {
		action("disconnect")
	}
	select {
	case err = <-done:
		if err != nil && f.Mode != "local" {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("revocation not received")
	}
	if !revoked(dir) {
		t.Fatal("missing durable revocation marker")
	}
	daemon.stop()
	if err = cleanupLocal(dir, s); err != nil {
		t.Fatal("cleanup:", err)
	}
	if s.Phase != "cleaned" || s.DevicePrivateKey != "" || s.SSHPublicKey != "" {
		t.Fatal("secret cleanup incomplete")
	}
	if _, err = os.Stat(filepath.Join(dir, "host_ed25519")); !os.IsNotExist(err) {
		t.Fatal("portable host key retained")
	}
	t.Log("native real-server protocol and lifecycle passed")
}
