package web

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"path"
	"strings"

	"github.com/maxb1906/arpent/assets"
	"github.com/maxb1906/arpent/internal/i18n"
)

// pages garde un jeu de modèles vierge par page (layout + page) ; chaque
// requête en clone un pour y attacher les fonctions de sa langue.
type pages struct {
	sets map[string]*template.Template
}

// baseFuncs : fonctions des modèles, liées à la langue de la requête.
func baseFuncs(tr *i18n.Translator) template.FuncMap { return i18n.TemplateFuncs(tr) }

func loadPages() (*pages, error) {
	sub, err := fs.Sub(assets.Web, "web/templates")
	if err != nil {
		return nil, err
	}
	files, err := fs.Glob(sub, "*.html")
	if err != nil {
		return nil, err
	}
	p := &pages{sets: map[string]*template.Template{}}
	var partials []string
	for _, f := range files {
		if strings.HasPrefix(f, "part_") {
			partials = append(partials, f)
		}
	}
	for _, f := range files {
		if strings.HasPrefix(f, "part_") || f == "layout.html" {
			continue
		}
		name := strings.TrimSuffix(path.Base(f), ".html")
		t, err := template.New("layout.html").Funcs(baseFuncs(nil)).ParseFS(sub, append([]string{"layout.html", f}, partials...)...)
		if err != nil {
			return nil, fmt.Errorf("modèle %s : %w", f, err)
		}
		p.sets[name] = t
	}
	return p, nil
}

// pageData est passé à chaque modèle.
type pageData struct {
	Lang    string
	Langs   []string
	Path    string
	Version string
	Running *jobSnapshot
	Title   string
	Data    any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	set, ok := s.pages.sets[name]
	if !ok {
		http.Error(w, "page inconnue", http.StatusInternalServerError)
		return
	}
	lang := s.lang(r)
	tr := s.opt.Bundle.Translator(lang)
	t, err := set.Clone()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.Funcs(baseFuncs(tr))
	pd := pageData{Lang: lang, Langs: s.opt.Bundle.Languages(), Path: r.URL.RequestURI(), Version: s.opt.Version, Data: data}
	if j := s.jobs.running(); j != nil {
		snap := j.snapshot()
		pd.Running = &snap
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", pd); err != nil {
		log.Printf("web: rendu %s : %v", name, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	buf.WriteTo(w)
}

// fail affiche une page d'erreur traduite.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, err error) {
	w.WriteHeader(status)
	s.render(w, r, "error", map[string]any{"Status": status, "Error": err.Error()})
}

func itoa64(i int64) string { return fmt.Sprint(i) }
