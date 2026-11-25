package main

import (
	"fmt"

	"github.com/maxb1906/arpent/internal/rawnet"
)

// cmdAdvanced indique si le mode avancé est disponible, et pourquoi.
func cmdAdvanced(e *env, args []string) int {
	fs := e.newFlags("advanced")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	st := rawnet.Check()
	if st.Available {
		fmt.Fprintln(e.stdout, e.T("advanced.available", "driver", st.Driver))
		return 0
	}
	fmt.Fprintln(e.stdout, e.T("advanced.unavailable")+" "+e.T(st.Reason))
	return 0
}
