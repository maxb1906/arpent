package main

import (
	"fmt"
	"runtime"
)

func cmdHello(e *env, _ []string) int {
	fmt.Fprintln(e.stdout, e.T("hello.greeting", "version", version, "os", runtime.GOOS, "arch", runtime.GOARCH))
	fmt.Fprintln(e.stdout, e.T("app.tagline"))
	fmt.Fprintln(e.stdout, e.T("hello.legal"))
	return 0
}
