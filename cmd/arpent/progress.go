package main

import (
	"fmt"
	"sync"
	"time"
)

// progress affiche l'avancement sur stderr, au plus quatre fois par seconde.
type progress struct {
	e    *env
	mu   sync.Mutex
	last time.Time
	any  bool
}

func newProgress(e *env) *progress { return &progress{e: e} }

func (p *progress) update(done, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if done != total && time.Since(p.last) < 250*time.Millisecond {
		return
	}
	p.last = time.Now()
	p.any = true
	fmt.Fprintf(p.e.stderr, "\r%s", p.e.T("progress.line", "done", fmt.Sprint(done), "total", fmt.Sprint(total)))
}

func (p *progress) done() {
	if p.any {
		fmt.Fprintln(p.e.stderr)
	}
}
