package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// progress affiche l'avancement sur stderr, au plus quatre fois par seconde.
type progress struct {
	e    *env
	mu   sync.Mutex
	last time.Time
	any  bool
	off  bool
}

// newProgress n'affiche rien si stderr n'est pas un terminal (journaux, tests).
func newProgress(e *env) *progress { return &progress{e: e, off: !isTerminal(e.stderr)} }

func isTerminal(w any) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func (p *progress) update(done, total int) {
	if p.off {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if done != total && time.Since(p.last) < 250*time.Millisecond {
		return
	}
	p.last = time.Now()
	p.any = true
	fmt.Fprintf(p.e.stderr, "\r%s   ", p.e.T("progress.line", "done", fmt.Sprint(done), "total", fmt.Sprint(total)))
}

func (p *progress) done() {
	if p.any {
		fmt.Fprintln(p.e.stderr)
	}
}
