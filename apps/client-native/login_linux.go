package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func installLogin(dir string, s *State, cleanup bool) error {
	suffix, command := "", "resume"
	if cleanup {
		suffix = "-cleanup"
		command = "cleanup"
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return e
	}
	path := filepath.Join(home, ".config", "systemd", "user", "nyaarink-"+s.Bootstrap.SessionID+suffix+".service")
	quote := func(v string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$").Replace(v) + `"`
	}
	root, e := stateRoot()
	if e != nil {
		return e
	}
	content := "[Unit]\nDescription=NyaaRink " + command + "\nAfter=network.target\n[Service]\nType=simple\nEnvironment=" + quote("XDG_DATA_HOME="+filepath.Dir(root)) + "\nExecStart=" + quote(filepath.Join(s.Runtime, binaryName())) + " " + command + " --session " + s.Bootstrap.SessionID + "\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=yes\nUMask=0077\n[Install]\nWantedBy=default.target\n"
	if _, e = localCommand("systemctl", "--user", "show-environment"); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	if old, e := os.ReadFile(path); e == nil && string(old) != content {
		return errors.New("conflicting login definition")
	}
	if cleanup {
		s.CleanupLoginFile = path
	} else {
		s.LoginFile = path
	}
	if e = writeState(dir, s); e != nil {
		return e
	}
	if e = durableWrite(path, []byte(content)); e != nil {
		return e
	}
	if e = exec.Command("systemctl", "--user", "daemon-reload").Run(); e != nil {
		return e
	}
	return exec.Command("systemctl", "--user", "enable", filepath.Base(path)).Run()
}
func removeLogin(s *State, cleanup bool) error {
	path := s.LoginFile
	if cleanup {
		path = s.CleanupLoginFile
	}
	if path == "" {
		return nil
	}
	if e := exec.Command("systemctl", "--user", "disable", filepath.Base(path)).Run(); e != nil {
		if _, stat := os.Stat(path); stat == nil {
			return e
		}
	}
	if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
		return e
	}
	return exec.Command("systemctl", "--user", "daemon-reload").Run()
}
