package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/maxb1906/arpent/assets"
	"github.com/maxb1906/arpent/internal/i18n"
)

// pages garde un jeu de modèles vierge par page (layout + page) ; chaque
// requête en clone un pour y attacher les fonctions de sa langue.
type pages struct {
	sets map[string]*template.Template
}

// baseFuncs : signatures des fonctions, redéfinies par requête.
func baseFuncs(tr *i18n.Translator) template.FuncMap {
	dateFmt, timeFmt := "02/01/2006", "02/01/2006 15:04"
	if tr != nil && tr.Lang() == "en" {
		dateFmt, timeFmt = "2006-01-02", "2006-01-02 15:04"
	}
	return template.FuncMap{
		"t": func(key string, pairs ...any) string {
			if tr == nil {
				return key
			}
			ss := make([]string, len(pairs))
			for i, p := range pairs {
				ss[i] = fmt.Sprint(p)
			}
			return tr.T(key, ss...)
		},
		"date": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.Local().Format(dateFmt)
		},
		"datetime": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.Local().Format(timeFmt)
		},
		"duration": func(a, b time.Time) string {
			if a.IsZero() || b.IsZero() {
				return "—"
			}
			d := b.Sub(a).Round(time.Second)
			if d < time.Minute {
				return strconv.Itoa(int(d.Seconds())) + " s"
			}
			return fmt.Sprintf("%d min %02d s", int(d.Minutes()), int(d.Seconds())%60)
		},
		"join":  strings.Join,
		"add":   func(a, b int) int { return a + b },
		"lower": strings.ToLower,
		"json": func(v any) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
		"daysUntil": func(t time.Time) int { return int(time.Until(t).Hours() / 24) },
		"past":      func(t time.Time) bool { return !t.IsZero() && time.Now().After(t) },
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
	}
}

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

func itoa64(i int64) string { return strconv.FormatInt(i, 10) }
