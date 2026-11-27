//go:build !windows

package main

func launchedAlone() bool { return false }

func showConsole(bool) {}
