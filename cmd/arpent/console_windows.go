package main

import (
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")

// launchedAlone indique que la console n'appartient qu'à ce processus :
// l'exe a été lancé par double-clic depuis l'Explorateur, et la fenêtre se
// fermera dès sa sortie.
func launchedAlone() bool {
	proc := kernel32.NewProc("GetConsoleProcessList")
	if proc.Find() != nil {
		return false
	}
	var pids [4]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// showConsole masque (false) ou réaffiche (true) la fenêtre de console. Ne
// fait rien si elle est partagée avec un autre processus (lancement depuis
// cmd ou PowerShell) : on ne cache pas le terminal de l'utilisateur.
func showConsole(show bool) {
	if !launchedAlone() {
		return
	}
	get := kernel32.NewProc("GetConsoleWindow")
	if get.Find() != nil {
		return
	}
	hwnd, _, _ := get.Call()
	if hwnd == 0 {
		return
	}
	proc := syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow")
	if proc.Find() != nil {
		return
	}
	const swHide, swShow = 0, 5
	cmd := uintptr(swHide)
	if show {
		cmd = swShow
	}
	proc.Call(hwnd, cmd)
}
