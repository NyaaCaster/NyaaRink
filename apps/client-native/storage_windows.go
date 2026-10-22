package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

func privatePath(path string) error {
	if e := rejectLinkedAncestors(path); e != nil {
		return e
	}
	stat, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if stat.Mode()&os.ModeSymlink != 0 {
		return errors.New("private path must not be a link")
	}
	if stat.Mode().IsRegular() {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		var info windows.ByHandleFileInformation
		err = windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info)
		f.Close()
		if err != nil {
			return err
		}
		if info.NumberOfLinks != 1 {
			return errors.New("private file must not have hard links")
		}
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	inherit := ""
	if stat.IsDir() {
		inherit = "OICI"
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;" + inherit + ";FA;;;" + user.User.Sid.String() + ")(A;" + inherit + ";FA;;;SY)")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func replaceFile(from, to string) error {
	f, e := windows.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	t, e := windows.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(f, t, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func replaceAuthorized(path string, data []byte) error { return durableWrite(path, data) }
func platformLock(path string) (func(), error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return nil, errors.New("client already running or lock inaccessible")
	}
	return func() { windows.CloseHandle(h) }, nil
}
func interactive() bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) == nil
}
func privilegedAccount() bool {
	admin, e := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if e != nil {
		return true
	}
	groups, e := windows.GetCurrentProcessToken().GetTokenGroups()
	if e != nil {
		return true
	}
	for _, g := range groups.AllGroups() {
		if windows.EqualSid(g.Sid, admin) {
			return true
		}
	}
	return false
}
func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
func verifyMicrosoft(path string) error {
	// WinVerifyTrust verifies embedded Authenticode against the Windows trust store.
	// Publisher pin is additionally enforced when building the fixed official ZIP.
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	info := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p}
	data := windows.WinTrustData{Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE, UnionChoice: windows.WTD_CHOICE_FILE, StateAction: windows.WTD_STATEACTION_VERIFY, ProvFlags: windows.WTD_CACHE_ONLY_URL_RETRIEVAL, FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&info)}
	verification := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeError := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	if verification != nil {
		return errors.New("OpenSSH Authenticode trust rejected")
	}
	return closeError
}
