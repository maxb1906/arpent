package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	// Copie de la sortie dans arpent-data/arpent.log (diagnostic quand la
	// fenêtre de console s'est fermée).
	if f, err := os.OpenFile(filepath.Join(dir, "arpent.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644); err == nil {
		defer f.Close()
		e.stdout, e.stderr = io.MultiWriter(e.stdout, f), io.MultiWriter(e.stderr, f)
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
