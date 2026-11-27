package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/maxb1906/arpent/internal/desktop"
	"github.com/maxb1906/arpent/internal/web"
)

func cmdUI(e *env, args []string) int {
	fs := e.newFlags("ui")
	browser := fs.Bool("browser", false, "")
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
	// fenêtre de console s'est fermée ou est masquée).
	if f, err := os.OpenFile(filepath.Join(dir, "arpent.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644); err == nil {
		defer f.Close()
		e.stdout, e.stderr = io.MultiWriter(e.stdout, f), io.MultiWriter(e.stderr, f)
	}
	ctx, stop := context.WithCancel(e.ctx)
	defer stop()

	srv, err := web.New(web.Options{DataDir: dir, Bundle: e.bundle, Lang: e.tr.Lang(), Port: *port, Version: version, OnQuit: stop})
	if err != nil {
		return e.fail(err)
	}
	fmt.Fprintln(e.stdout, e.T("ui.started", "url", srv.URL()))
	fmt.Fprintln(e.stdout, e.T("ui.data", "dir", dir))

	// Fenêtre Arpent (Windows + WebView2) par défaut, sinon navigateur.
	useWindow := desktop.Supported && !*browser && !*noBrowser
	if useWindow {
		if ok, reason := desktop.Available(); !ok {
			useWindow = false
			fmt.Fprintln(e.stderr, e.T("ui.window_unavailable", "reason", reason))
		}
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx) }()

	if useWindow {
		// « Quitter » (ou Ctrl+C) arrête le serveur puis ferme la fenêtre.
		var mu sync.Mutex
		var closeWindow func()
		go func() {
			<-ctx.Done()
			mu.Lock()
			defer mu.Unlock()
			if closeWindow != nil {
				closeWindow()
			}
		}()
		fmt.Fprintln(e.stdout, e.T("ui.window"))
		showConsole(false)
		err := desktop.Run(desktop.Options{
			Title:   "Arpent",
			URL:     srv.URL(),
			DataDir: dir,
			Messages: desktop.Messages{
				Error:          e.T("ui.window_error"),
				ProcessCrash:   e.T("ui.window_crash"),
				MissingRuntime: e.T("ui.window_missing"),
			},
			OnReady: func(close func()) {
				mu.Lock()
				closeWindow = close
				mu.Unlock()
				if ctx.Err() != nil { // « Quitter » avant l'ouverture complète
					close()
				}
			},
		})
		mu.Lock()
		closeWindow = nil
		mu.Unlock()
		if err == nil || ctx.Err() != nil {
			stop() // fenêtre fermée : on arrête tout
		} else {
			// La fenêtre n'a pas pu s'ouvrir : on retombe sur le navigateur.
			showConsole(true)
			fmt.Fprintln(e.stderr, e.T("ui.window_unavailable", "reason", err.Error()))
			useWindow = false
		}
	}
	if !useWindow {
		fmt.Fprintln(e.stdout, e.T("ui.stop"))
		if !*noBrowser {
			if err := web.OpenBrowser(srv.URL()); err != nil {
				fmt.Fprintln(e.stderr, e.T("ui.no_browser"))
			}
		}
	}
	if err := <-served; err != nil {
		return e.fail(err)
	}
	fmt.Fprintln(e.stdout, e.T("ui.stopped"))
	return 0
}
