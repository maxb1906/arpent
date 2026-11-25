package web

import "os/exec"

// OpenBrowser ouvre url dans le navigateur par défaut.
func OpenBrowser(url string) error { return exec.Command("open", url).Start() }
