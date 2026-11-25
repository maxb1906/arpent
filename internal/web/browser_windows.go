package web

import (
	"os/exec"
	"syscall"
)

// OpenBrowser ouvre url dans le navigateur par défaut.
func OpenBrowser(url string) error {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}
