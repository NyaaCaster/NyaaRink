package main

import (
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"unsafe"
)

// Explicit opt-in: run only the isolated SSH probe under the existing limited
// token. Never change services or create users to manufacture test coverage.
func TestPortableLimitedToken(t *testing.T) {
	if os.Getenv("NYAARINK_LIMITED_PROBE") != "1" {
		t.Skip("explicit isolated Windows probe only")
	}
	current := windows.GetCurrentProcessToken()
	token, err := current.GetLinkedToken()
	if err != nil {
		var opened windows.Token
		if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &opened); err != nil {
			t.Fatal(err)
		}
		defer opened.Close()
		admin, e := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if e != nil {
			t.Fatal(e)
		}
		disabled := windows.SIDAndAttributes{Sid: admin}
		api := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
		ok, _, e := api.Call(uintptr(opened), 1, 1, uintptr(unsafe.Pointer(&disabled)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&token)))
		if ok == 0 {
			t.Fatal(e)
		}
		t.Log("No linked UAC token; restricted token disables administrators SID and all nonessential privileges; not a separate ordinary account")
	}
	defer token.Close()
	identity, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;" + identity.User.Sid.String() + ")(A;;GA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	defaultDacl := struct{ Dacl *windows.ACL }{acl}
	setInfo := windows.NewLazySystemDLL("advapi32.dll").NewProc("SetTokenInformation")
	ok, _, err := setInfo.Call(uintptr(token), uintptr(windows.TokenDefaultDacl), uintptr(unsafe.Pointer(&defaultDacl)), unsafe.Sizeof(defaultDacl))
	if ok == 0 {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestPortableChild", "-test.v")
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token), HideWindow: true}
	cmd.Env = append(os.Environ(), "NYAARINK_PROBE_CHILD=1")
	out, err := cmd.CombinedOutput()
	t.Log(string(out))
	if err != nil {
		t.Fatal(err)
	}
}
