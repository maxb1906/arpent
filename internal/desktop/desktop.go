// Package desktop affiche l'interface d'Arpent dans une fenêtre native
// (Wails v2 + WebView2 sous Windows) au lieu du navigateur par défaut.
//
// La fenêtre ne réimplémente rien : elle ouvre l'adresse du serveur local
// de internal/web (127.0.0.1, jeton de session), exactement comme le
// navigateur. Formulaires, téléchargements, rapports et PDF fonctionnent
// donc à l'identique dans les deux modes.
//
// Seul Windows est pris en charge : Wails y est pur Go (pas de CGO), alors
// que Linux (WebKitGTK) et macOS (WebKit) exigent CGO. Ailleurs, et sous
// Windows sans le runtime WebView2, Arpent revient au navigateur. Le code
// Wails n'est compilé qu'avec les tags « desktop,production » (make
// windows) : sans eux, Wails afficherait une erreur au lancement.
package desktop

import (
	"errors"
	"html"
	"net/http"
)

// Options règle la fenêtre.
type Options struct {
	Title string
	// URL est l'adresse de connexion du serveur local (avec le jeton).
	URL string
	// DataDir reçoit le profil WebView2 (dossier webview2/) : rien n'est
	// écrit dans le profil Windows de l'utilisateur.
	DataDir string
	// Messages traduits affichés par Wails si WebView2 fait défaut.
	Messages Messages
	// OnReady reçoit la fonction qui ferme la fenêtre (bouton « Quitter »).
	OnReady func(quit func())
}

// Messages traduits utilisés par la fenêtre.
type Messages struct {
	Error          string
	ProcessCrash   string
	MissingRuntime string
}

// ErrUnavailable : la fenêtre native ne peut pas être ouverte ici.
var ErrUnavailable = errors.New("desktop window unavailable")

// Redirect sert, à l'adresse interne de Wails, une page qui part aussitôt
// vers le serveur local. Pas de script : un simple meta refresh.
func Redirect(target string) http.Handler {
	page := `<!doctype html><html><head><meta charset="utf-8">` +
		`<meta http-equiv="refresh" content="0;url=` + html.EscapeString(target) + `">` +
		`<title>Arpent</title></head><body></body></html>`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(page))
	})
}
