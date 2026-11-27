//go:build windows && production

package desktop

import (
	"context"
	"path/filepath"

	"github.com/wailsapp/go-webview2/webviewloader"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// Supported : la fenêtre native est compilée dans cet exécutable.
const Supported = true

// Available vérifie la présence du runtime WebView2 (livré avec Windows 11
// et les Windows 10 à jour). Arpent ne l'installe jamais lui-même : on est
// sur le PC d'un client.
func Available() (bool, string) {
	v, err := webviewloader.GetAvailableCoreWebView2BrowserVersionString("")
	if err != nil {
		return false, err.Error()
	}
	if v == "" {
		return false, "WebView2 runtime not installed"
	}
	return true, ""
}

// Run ouvre la fenêtre et rend la main quand elle est fermée.
func Run(o Options) error {
	if ok, _ := Available(); !ok {
		return ErrUnavailable
	}
	msgs := windows.DefaultMessages()
	if o.Messages.Error != "" {
		msgs.Error = o.Messages.Error
	}
	if o.Messages.ProcessCrash != "" {
		msgs.WebView2ProcessCrash = o.Messages.ProcessCrash
	}
	if o.Messages.MissingRuntime != "" {
		msgs.MissingRequirements = o.Messages.MissingRuntime
		msgs.Webview2NotInstalled = o.Messages.MissingRuntime
	}
	return wails.Run(&options.App{
		Title:     o.Title,
		Width:     1280,
		Height:    860,
		MinWidth:  900,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Handler: Redirect(o.URL),
		},
		OnStartup: func(ctx context.Context) {
			if o.OnReady != nil {
				o.OnReady(func() { runtime.Quit(ctx) })
			}
		},
		Windows: &windows.Options{
			WebviewUserDataPath: filepath.Join(o.DataDir, "webview2"),
			Theme:               windows.SystemDefault,
			Messages:            msgs,
		},
	})
}
