package main

import (
	"fmt"
	"path/filepath"
	"slices"

	"github.com/maxb1906/arpent/internal/report"
)

func cmdReport(e *env, args []string) int {
	fs := e.newFlags("report")
	site := fs.String("site", "", "")
	id := fs.Int64("audit", 0, "")
	format := fs.String("format", "html", "")
	lang := fs.String("report-lang", "", "")
	out := fs.String("out", "", "")
	kind := fs.String("kind", report.KindFull, "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	if !slices.Contains(report.Kinds, *kind) {
		return e.fail(fmt.Errorf("type : %s", *kind))
	}
	if !slices.Contains(report.Formats, *format) {
		return e.fail(fmt.Errorf("format : %s", *format))
	}
	rl := e.tr.Lang()
	if *lang == "" {
		*lang = e.config().ReportLang
	}
	if *lang != "" {
		if !e.bundle.Has(*lang) {
			return e.fail(fmt.Errorf("langue : %s", *lang))
		}
		rl = *lang
	}
	s, err := e.openSite(*site)
	if err != nil {
		return e.fail(err)
	}
	defer s.Close()
	if *id == 0 {
		if *id, err = s.LatestAudit(); err != nil {
			return e.fail(err)
		}
		if *id == 0 {
			fmt.Fprintln(e.stdout, e.T("site.no_audit"))
			return 1
		}
	}
	d, err := report.Build(s, *id, "Arpent "+version)
	if err != nil {
		return e.fail(err)
	}
	applyIssuer(e, d)
	d.Kind = *kind
	tr := e.bundle.Translator(rl)
	if *format == "pdf" {
		path := *out
		if path == "" || path == "-" {
			path = report.KindPath(s, d.Audit, d.Kind, "pdf")
		}
		if err := report.PDFFile(e.ctx, path, d, tr); err != nil {
			return e.fail(err)
		}
		fmt.Fprintln(e.stdout, e.T("report.written", "path", path))
		return 0
	}
	if *out == "-" {
		if err := report.Write(e.stdout, *format, d, tr); err != nil {
			return e.fail(err)
		}
		return 0
	}
	path := *out
	if path == "" {
		path = report.KindPath(s, d.Audit, d.Kind, *format)
	}
	if err := report.WriteFile(path, *format, d, tr); err != nil {
		return e.fail(err)
	}
	fmt.Fprintln(e.stdout, e.T("report.written", "path", path))
	return 0
}

// applyIssuer complète l'émetteur du rapport avec le profil de config.yaml.
func applyIssuer(e *env, d *report.Data) {
	if dir, err := e.dataDir(); err == nil {
		d.Issuer = report.IssuerFromConfig(dir, e.config().Issuer)
		report.TemplatesDir = filepath.Join(dir, "templates")
	}
}

func cmdTemplates(e *env, args []string) int {
	fs := e.newFlags("templates")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	dir, err := e.dataDir()
	if err != nil {
		return e.fail(err)
	}
	tdir := filepath.Join(dir, "templates")
	written, err := report.ExportTemplates(tdir)
	if err != nil {
		return e.fail(err)
	}
	if len(written) == 0 {
		fmt.Fprintln(e.stdout, e.T("templates.exists", "dir", tdir))
	}
	for _, p := range written {
		fmt.Fprintln(e.stdout, e.T("templates.written", "path", p))
	}
	return 0
}
