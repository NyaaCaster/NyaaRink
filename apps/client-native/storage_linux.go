package main

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func privatePath(path string) error {
	if e := rejectLinkedAncestors(path); e != nil {
		return e
	}
	stat, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if stat.Mode()&os.ModeSymlink != 0 || stat.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe private path permissions")
	}
	if stat.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return errors.New("private path owner mismatch")
	}
	if stat.Mode().IsRegular() && stat.Sys().(*syscall.Stat_t).Nlink != 1 {
		return errors.New("private file must not have hard links")
	}
	return nil
}
func replaceFile(from, to string) error {
	if e := os.Rename(from, to); e != nil {
		return e
	}
	f, e := os.Open(filepath.Dir(to))
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func platformLock(path string) (func(), error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("client already running")
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
func interactive() bool {
	_, e := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return e == nil
}
func privilegedAccount() bool { return os.Getuid() == 0 }
func replaceAuthorized(path string, data []byte) error {
	stat, e := os.Lstat(path)
	if e != nil {
		return e
	}
	// Retain mode and every extended attribute, including a POSIX access ACL.
	tmp := filepath.Join(filepath.Dir(path), ".key-"+randomID())
	defer os.Remove(tmp)
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, stat.Mode().Perm())
	if e != nil {
		return e
	}
	if e = copyXattrs(path, tmp); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(data); e == nil {
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
func copyXattrs(from, to string) error {
	n, err := unix.Llistxattr(from, nil)
	if errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	if err != nil {
		return err
	}
	if n > 65536 {
		return errors.New("extended attributes too large")
	}
	names := make([]byte, n)
	n, err = unix.Llistxattr(from, names)
	if err != nil {
		return err
	}
	for _, name := range strings.Split(string(names[:n]), "\x00") {
		if name == "" {
			continue
		}
		size, err := unix.Lgetxattr(from, name, nil)
		if err != nil {
			return err
		}
		if size > 65536 {
			return errors.New("extended attribute too large")
		}
		value := make([]byte, size)
		size, err = unix.Lgetxattr(from, name, value)
		if err != nil {
			return err
		}
		if err = unix.Lsetxattr(to, name, value[:size], 0); err != nil {
			return err
		}
	}
	return nil
}
