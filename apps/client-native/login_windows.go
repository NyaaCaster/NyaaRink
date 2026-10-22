package main

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"unicode/utf16"
)

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func installLogin(dir string, s *State, cleanup bool) error {
	suffix, command := "", "resume"
	if cleanup {
		suffix = "-cleanup"
		command = "cleanup"
	}
	path := filepath.Join(dir, "native-login"+suffix+".xml")
	who, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	sid := who.User.Sid.String()
	content := `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><LogonTrigger><Enabled>true</Enabled><UserId>` + sid + `</UserId></LogonTrigger></Triggers><Principals><Principal id="Target"><UserId>` + sid + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings><Actions Context="Target"><Exec><Command>` + xmlText(filepath.Join(s.Runtime, binaryName())) + `</Command><Arguments>` + command + ` --session ` + s.Bootstrap.SessionID + `</Arguments><WorkingDirectory>` + xmlText(s.Runtime) + `</WorkingDirectory></Exec></Actions></Task>`
	units := utf16.Encode([]rune("\ufeff" + content))
	data := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(data[i*2:], u)
	}
	if cleanup {
		s.CleanupLoginFile = path
	} else {
		s.LoginFile = path
	}
	if e = writeState(dir, s); e != nil {
		return e
	}
	if e = durableWrite(path, data); e != nil {
		return e
	}
	cmd := exec.Command("schtasks.exe", "/Create", "/TN", "NyaaRink-"+s.Bootstrap.SessionID+suffix, "/XML", path, "/F")
	cmd.SysProcAttr = hiddenProcess()
	out, e := cmd.CombinedOutput()
	if e != nil {
		return errors.New("login registration failed: " + string(out))
	}
	return nil
}
func removeLogin(s *State, cleanup bool) error {
	suffix, path := "", s.LoginFile
	if cleanup {
		suffix = "-cleanup"
		path = s.CleanupLoginFile
	}
	if path == "" {
		return nil
	}
	// A failed query is not treated as proof that a task is absent.
	script := `$ErrorActionPreference='Stop';$s=New-Object -ComObject 'Schedule.Service';$s.Connect();$f=$s.GetFolder('\');$name='NyaaRink-` + s.Bootstrap.SessionID + suffix + `';$t=@($f.GetTasks(0)|Where-Object {$_.Name -eq $name});if($t.Count){$f.DeleteTask($name,0)}`
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = hiddenProcess()
	if out, e := cmd.CombinedOutput(); e != nil {
		return errors.New("login removal failed: " + string(out))
	}
	if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
		return e
	}
	return nil
}
