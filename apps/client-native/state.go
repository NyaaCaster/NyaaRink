package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

type State struct {
	// Test fixtures may supply an isolated CA; production uses the system store.
	tlsConfig        *tls.Config
	V                int         `json:"v"`
	Bootstrap        Bootstrap   `json:"bootstrap"`
	DevicePrivateKey string      `json:"devicePrivateKey,omitempty"`
	DevicePublicKey  string      `json:"devicePublicKey"`
	Enrollment       *Enrollment `json:"enrollment,omitempty"`
	Phase            string      `json:"phase"`
	SSHPublicKey     string      `json:"sshPublicKey,omitempty"`
	AuthorizedKeys   string      `json:"authorizedKeys,omitempty"`
	LoginFile        string      `json:"loginFile,omitempty"`
	CleanupLoginFile string      `json:"cleanupLoginFile,omitempty"`
	Runtime          string      `json:"runtime"`
	Cleanup          string      `json:"cleanup"`
	Reported         bool        `json:"reported"`
	ReleaseVersion   string      `json:"releaseVersion"`
	Native           bool        `json:"native,omitempty"`
}

func rejectLinkedAncestors(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		stat, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if stat.Mode()&os.ModeSymlink != 0 {
			return errors.New("linked private path refused")
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func stateRoot() (string, error) {
	if runtime.GOOS == "windows" {
		if root := os.Getenv("LOCALAPPDATA"); root != "" {
			return filepath.Join(root, "NyaaRink"), nil
		}
		return "", errors.New("LOCALAPPDATA unavailable")
	}
	root := os.Getenv("XDG_DATA_HOME")
	if root == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", e
		}
		root = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(root, "nyaarink"), nil
}
func stateDirectory(id string) (string, error) {
	if !uuidPattern.MatchString(id) {
		return "", errors.New("invalid session ID")
	}
	root, e := stateRoot()
	if e != nil {
		return "", e
	}
	dir := filepath.Join(root, id)
	for _, p := range []string{root, dir} {
		if e = os.MkdirAll(p, 0700); e != nil {
			return "", e
		}
		if e = privatePath(p); e != nil {
			return "", e
		}
	}
	return dir, nil
}
func revoked(dir string) bool { _, e := os.Lstat(filepath.Join(dir, "revoked")); return e == nil }
func durableWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, e := os.OpenFile(filepath.Join(dir, ".tmp-"+randomID()), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = privatePath(tmp); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return replaceFile(tmp, path)
}
func writeState(dir string, s *State) error {
	if e := s.Bootstrap.validate(); e != nil {
		return e
	}
	if !filepath.IsAbs(s.Runtime) || s.Bootstrap.SessionID != filepath.Base(dir) {
		return errors.New("state identity mismatch")
	}
	if revoked(dir) && s.Phase != "revoked" && s.Phase != "cleaned" {
		return errors.New("local revocation is permanent")
	}
	data, e := wireJSON(s)
	if e != nil {
		return e
	}
	return durableWrite(filepath.Join(dir, "state.json"), data)
}
func readState(dir string) (*State, error) {
	path := filepath.Join(dir, "state.json")
	if e := privatePath(path); e != nil {
		return nil, e
	}
	data, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(data) > 65536 {
		return nil, errors.New("state too large")
	}
	var s State
	if e = json.Unmarshal(data, &s); e != nil {
		return nil, e
	}
	if e = s.Bootstrap.validate(); e != nil {
		return nil, e
	}
	if s.V != 1 || s.Bootstrap.SessionID != filepath.Base(dir) || !s.Native {
		return nil, errors.New("state is not native; existing sessions must use their original runtime")
	}
	if revoked(dir) && s.Phase != "cleaned" {
		s.Phase = "revoked"
	}
	return &s, nil
}
func writerLock(dir string) (func(), error) {
	return platformLock(filepath.Join(dir, "native-writer.lock"))
}
