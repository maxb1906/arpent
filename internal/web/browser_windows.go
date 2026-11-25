package web

import (
	"errors"
	"os/exec"
	"syscall"
	"unsafe"
)

// OpenBrowser ouvre url dans le navigateur par défaut : ShellExecuteW
// (shell32), puis rundll32 en secours.
func OpenBrowser(url string) error {
	if shellOpen(url) == nil {
		return nil
	}
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}

func shellOpen(url string) error {
	proc := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")
	if err := proc.Find(); err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("open")
	target, err := syscall.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	const swShowNormal = 1
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)), 0, 0, swShowNormal)
	if r <= 32 { // code d'erreur ShellExecute
		return errors.New("ShellExecute failed")
	}
	return nil
}
