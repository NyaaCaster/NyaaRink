package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

var version = "0.1.0"

const releasePublicKey = "MCowBQYDK2VwAyEAIskGwyA9SGKvxdPqgsMAH8uA8P0RMyDSz4l/2LK654Y="

type Manifest struct {
	V             int               `json:"v"`
	Version       string            `json:"version"`
	Platform      string            `json:"platform"`
	Arch          string            `json:"arch"`
	Runtime       string            `json:"runtime"`
	GoVersion     string            `json:"goVersion"`
	MinimumSystem string            `json:"minimumSystem"`
	Files         map[string]string `json:"files"`
}

func binaryName() string {
	if runtime.GOOS == "windows" {
		return "nyaarink-client.exe"
	}
	return "nyaarink-client"
}
func wirePlatform() string {
	if runtime.GOOS == "windows" {
		return "win32"
	}
	return runtime.GOOS
}
func verifyRelease(dir string) error {
	data, e := readReleaseMetadata(filepath.Join(dir, "manifest.json"), 32768)
	if e != nil {
		return e
	}
	if len(data) > 32768 {
		return errors.New("manifest too large")
	}
	signature, e := readReleaseMetadata(filepath.Join(dir, "manifest.sig"), 64)
	if e != nil {
		return e
	}
	der, e := base64.StdEncoding.DecodeString(releasePublicKey)
	if e != nil {
		return e
	}
	key, e := x509.ParsePKIXPublicKey(der)
	if e != nil {
		return e
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(pub, data, signature) {
		return errors.New("release signature invalid")
	}
	var m Manifest
	if e = strictJSON(data, &m); e != nil {
		return e
	}
	if m.V != 2 || m.Version != version || m.Runtime != "go" || m.Platform != wirePlatform() || m.Arch != "x64" {
		return errors.New("release identity mismatch")
	}
	required := []string{binaryName(), "LICENSE", "THIRD-PARTY-NOTICES"}
	if runtime.GOOS == "windows" {
		required = append(required, "sshd.exe", "sshd-auth.exe", "sshd-session.exe", "ssh-shellhost.exe", "sftp-server.exe", "libcrypto.dll", "OPENSSH-LICENSE.txt", "OPENSSH-NOTICE.txt")
	}
	for _, name := range required {
		if m.Files[name] == "" {
			return fmt.Errorf("incomplete release: %s", name)
		}
	}
	names := regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	hash := regexp.MustCompile(`^[a-f0-9]{64}$`)
	for name, sum := range m.Files {
		if !names.MatchString(name) || !hash.MatchString(sum) {
			return errors.New("invalid release entry")
		}
		path := filepath.Join(dir, name)
		stat, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if !stat.Mode().IsRegular() {
			return errors.New("release entry not regular")
		}
		if stat.Size() > 64*1024*1024 {
			return errors.New("release entry too large")
		}
		contents, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if digest(contents) != sum {
			return fmt.Errorf("release file rejected: %s", name)
		}
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if _, ok := m.Files[entry.Name()]; !ok && entry.Name() != "manifest.json" && entry.Name() != "manifest.sig" {
			return errors.New("unexpected release entry")
		}
	}
	return nil
}
func readReleaseMetadata(path string, maximum int64) ([]byte, error) {
	stat, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > maximum {
		return nil, errors.New("invalid release metadata")
	}
	return os.ReadFile(path)
}
func installRuntime(source string) (string, error) {
	if e := verifyRelease(source); e != nil {
		return "", e
	}
	root, e := stateRoot()
	if e != nil {
		return "", e
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return "", e
	}
	if e = privatePath(root); e != nil {
		return "", e
	}
	data, e := os.ReadFile(filepath.Join(source, "manifest.json"))
	if e != nil {
		return "", e
	}
	dest := filepath.Join(root, "runtime-native-"+version+"-"+digest(data))
	if _, e = os.Lstat(dest); e == nil {
		return dest, verifyRelease(dest)
	}
	staging := filepath.Join(root, ".runtime-"+randomID())
	if e = os.Mkdir(staging, 0700); e != nil {
		return "", e
	}
	defer os.RemoveAll(staging)
	if e = privatePath(staging); e != nil {
		return "", e
	}
	entries, e := os.ReadDir(source)
	if e != nil {
		return "", e
	}
	for _, entry := range entries {
		data, e := os.ReadFile(filepath.Join(source, entry.Name()))
		if e != nil {
			return "", e
		}
		path := filepath.Join(staging, entry.Name())
		mode := os.FileMode(0600)
		if entry.Name() == binaryName() {
			mode = 0700
		}
		if e = os.WriteFile(path, data, mode); e != nil {
			return "", e
		}
		if e = privatePath(path); e != nil {
			return "", e
		}
	}
	if e = verifyRelease(staging); e != nil {
		return "", e
	}
	if e = os.Rename(staging, dest); e != nil {
		if existing := verifyRelease(dest); existing != nil {
			return "", e
		}
	}
	return dest, nil
}
