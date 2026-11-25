// Package web sert l'interface locale d'Arpent : un serveur HTTP qui
// n'écoute que sur 127.0.0.1 (jamais sur le réseau audité), protégé par un
// jeton de session aléatoire et par la vérification de l'en-tête Host
// (contre le « DNS rebinding »). Pages HTML rendues côté serveur, un peu
// de JavaScript sans dépendance, tout est embarqué dans l'exécutable.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/maxb1906/arpent/internal/i18n"
	"github.com/maxb1906/arpent/internal/report"
)

const (
	sessionCookie = "arpent_session"
	langCookie    = "arpent_lang"
)

// Options règle le serveur.
type Options struct {
	DataDir string
	Bundle  *i18n.Bundle
	Lang    string // langue par défaut de l'interface
	Port    int    // 0 : port libre choisi par l'OS
	Version string
	// OnQuit est appelé quand l'utilisateur clique « Quitter ».
	OnQuit func()
	// Issuer fournit l'émetteur des rapports (profil du technicien).
	Issuer func() report.Issuer
}

// Server est l'interface web.
type Server struct {
	opt    Options
	token  string
	addr   string // 127.0.0.1:port
	jobs   *jobs
	pages  *pages
	mux    *http.ServeMux
	server *http.Server
	ln     net.Listener
}

// New prépare le serveur et réserve le port d'écoute.
func New(opt Options) (*Server, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(opt.Port)))
	if err != nil {
		return nil, err
	}
	p, err := loadPages()
	if err != nil {
		ln.Close()
		return nil, err
	}
	s := &Server{opt: opt, token: hex.EncodeToString(b), addr: ln.Addr().String(), jobs: newJobs(), pages: p, ln: ln}
	s.routes()
	s.server = &http.Server{Handler: s.guard(s.mux), ReadHeaderTimeout: 10 * time.Second}
	return s, nil
}

// URL est l'adresse à ouvrir dans le navigateur (avec le jeton de session).
func (s *Server) URL() string { return "http://" + s.addr + "/login?k=" + s.token }

// Addr renvoie 127.0.0.1:port.
func (s *Server) Addr() string { return s.addr }

// Serve sert les requêtes jusqu'à l'annulation de ctx.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.jobs.cancelAll()
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.server.Shutdown(c)
	}()
	err := s.server.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// guard vérifie l'hôte demandé et le jeton de session.
func (s *Server) guard(next http.Handler) http.Handler {
	_, port, _ := net.SplitHostPort(s.addr)
	allowed := map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed[strings.ToLower(r.Host)] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'")
		if r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.token)) != 1 {
			http.Error(w, "session absente : ouvrez l'adresse affichée par Arpent / no session: open the address printed by Arpent", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Requêtes modifiantes : même origine obligatoire.
			if o := r.Header.Get("Origin"); o != "" && !allowed[strings.TrimPrefix(strings.ToLower(o), "http://")] {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("k")), []byte(s.token)) != 1 {
		http.Error(w, "jeton invalide / invalid token", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// lang renvoie la langue de l'interface pour cette requête.
func (s *Server) lang(r *http.Request) string {
	if c, err := r.Cookie(langCookie); err == nil && s.opt.Bundle.Has(c.Value) {
		return c.Value
	}
	return s.opt.Lang
}

func (s *Server) setLang(w http.ResponseWriter, r *http.Request) {
	l := r.FormValue("lang")
	if s.opt.Bundle.Has(l) {
		http.SetCookie(w, &http.Cookie{Name: langCookie, Value: l, Path: "/", MaxAge: 365 * 24 * 3600, SameSite: http.SameSiteStrictMode})
	}
	back := r.FormValue("back")
	if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") {
		back = "/"
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (s *Server) quit(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "quit", nil)
	if s.opt.OnQuit != nil {
		go func() { time.Sleep(300 * time.Millisecond); s.opt.OnQuit() }()
	}
}
