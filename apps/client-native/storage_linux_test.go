package main

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthorizedMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Lsetxattr(path, "user.nyaarink-test", []byte("preserve"), 0); err != nil {
		t.Fatal(err)
	}
	if err := replaceAuthorized(path, []byte("original\nnew\n")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 64)
	n, err := unix.Lgetxattr(path, "user.nyaarink-test", data)
	if err != nil || string(data[:n]) != "preserve" {
		t.Fatal("extended attribute lost", err)
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("mode lost", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if err := privatePath(path); err == nil {
		t.Fatal("hardlink accepted")
	}
}
