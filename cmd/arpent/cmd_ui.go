package main

import (
	"context"
	"fmt"

	"github.com/maxb1906/arpent/internal/web"
)

func cmdUI(e *env, args []string) int {
	fs := e.newFlags("ui")
	noBrowser := fs.Bool("no-browser", false, "")
	port := fs.Int("port", 0, "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	dir, err := e.dataDir()
	if err != nil {
		return e.fail(err)
	}
	ctx, quit := context.WithCancel(e.ctx)
	defer quit()
	srv, err := web.New(web.Options{DataDir: dir, Bundle: e.bundle, Lang: e.tr.Lang(), Port: *port, Version: version, OnQuit: quit})
	if err != nil {
		return e.fail(err)
	}
	fmt.Fprintln(e.stdout, e.T("ui.started", "url", srv.URL()))
	fmt.Fprintln(e.stdout, e.T("ui.data", "dir", dir))
	fmt.Fprintln(e.stdout, e.T("ui.stop"))
	if !*noBrowser {
		if err := web.OpenBrowser(srv.URL()); err != nil {
			fmt.Fprintln(e.stderr, e.T("ui.no_browser"))
		}
	}
	if err := srv.Serve(ctx); err != nil {
		return e.fail(err)
	}
	fmt.Fprintln(e.stdout, e.T("ui.stopped"))
	return 0
}
