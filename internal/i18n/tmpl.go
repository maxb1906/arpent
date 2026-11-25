package i18n

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strconv"
	"strings"
	"time"
)

// TemplateFuncs renvoie les fonctions communes aux modèles HTML (interface
// et rapport), liées au traducteur tr (nil : clés brutes, pour l'analyse).
func TemplateFuncs(tr *Translator) template.FuncMap {
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
		// ft traduit un texte de règle : ft "telnet" "title" params.
		"ft": func(rule, part string, params map[string]string) string {
			if tr == nil {
				return rule
			}
			pairs := make([]string, 0, 2*len(params))
			for k, v := range params {
				pairs = append(pairs, k, v)
			}
			return tr.T("rule."+rule+"."+part, pairs...)
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
