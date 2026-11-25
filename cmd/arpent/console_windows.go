package main

import (
	"syscall"
	"unsafe"
)

// launchedAlone indique que la console n'appartient qu'à ce processus :
// l'exe a été lancé par double-clic depuis l'Explorateur, et la fenêtre se
// fermera dès sa sortie.
func launchedAlone() bool {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	if proc.Find() != nil {
		return false
	}
	var pids [4]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}
