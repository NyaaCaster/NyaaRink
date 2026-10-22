package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

func hiddenProcess() *syscall.SysProcAttr { return &syscall.SysProcAttr{HideWindow: true} }

func resumeInitialThread(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != pid {
			continue
		}
		thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(thread)
		count, err := windows.ResumeThread(thread)
		if err != nil {
			return err
		}
		if count != 1 {
			return errors.New("unexpected portable SSH thread state")
		}
		return nil
	}
	return errors.New("portable SSH initial thread unavailable")
}
