package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/maxb1906/arpent/internal/diff"
	"github.com/maxb1906/arpent/internal/store"
)

func cmdExport(e *env, args []string) int {
	fs := e.newFlags("export")
	site := fs.String("site", "", "")
	out := fs.String("out", "", "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	s, err := e.openSite(*site)
	if err != nil {
		return e.fail(err)
	}
	defer s.Close()
	path := *out
	if path == "" {
		path = s.Slug + "_" + time.Now().Format("2006-01-02") + store.ArchiveExt
	}
	f, err := os.Create(path)
	if err != nil {
		return e.fail(err)
	}
	if err := s.Export(f); err != nil {
		f.Close()
		os.Remove(path)
		return e.fail(err)
	}
	if err := f.Close(); err != nil {
		return e.fail(err)
	}
	fmt.Fprintln(e.stdout, e.T("export.done", "path", path))
	return 0
}

func cmdImport(e *env, args []string) int {
	fs := e.newFlags("import")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(e.stderr, e.T("import.usage"))
		return 2
	}
	dir, err := e.dataDir()
	if err != nil {
		return e.fail(err)
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return e.fail(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return e.fail(err)
	}
	res, err := store.Import(dir, f, st.Size())
	if err != nil {
		return e.fail(err)
	}
	if s, err := store.OpenSite(dir, res.Slug); err == nil {
		err = diff.RecomputeAll(s)
		s.Close()
		if err != nil {
			return e.fail(err)
		}
	}
	fmt.Fprintln(e.stdout, e.T("import.done", "site", res.Name, "added", strconv.Itoa(res.Added), "skipped", strconv.Itoa(res.Skipped), "reports", strconv.Itoa(res.Reports)))
	return 0
}

func cmdSearch(e *env, args []string) int {
	fs := e.newFlags("search")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	q := strings.Join(fs.Args(), " ")
	if strings.TrimSpace(q) == "" {
		fmt.Fprintln(e.stderr, e.T("search.usage"))
		return 2
	}
	dir, err := e.dataDir()
	if err != nil {
		return e.fail(err)
	}
	hits, err := store.Search(dir, q)
	if err != nil {
		return e.fail(err)
	}
	fmt.Fprintln(e.stdout, e.T("web.search_results", "count", strconv.Itoa(len(hits)), "q", q))
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	for _, h := range hits {
		port := ""
		if h.Port != 0 {
			port = fmt.Sprintf("%d/%s", h.Port, h.Proto)
		}
		val := h.Value
		if h.Field == "finding" {
			val = e.T("rule."+h.Value+".title", "port", strconv.Itoa(h.Port))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", h.Site.Name, h.IP, dash(port), e.T("web.field."+h.Field), val)
	}
	tw.Flush()
	return 0
}
