//go:build !windows && !darwin

package web

import (
	"errors"
	"os"
	"os/exec"
)

// OpenBrowser ouvre url dans le navigateur par défaut (session graphique requise).
func OpenBrowser(url string) error {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return errors.New("pas de session graphique")
	}
	return exec.Command("xdg-open", url).Start()
}
