package main

import (
	"flag"
	"fmt"
	"io"
	"strconv"

	"github.com/maxb1906/arpent/internal/store"
)

func cmdAnnotate(e *env, args []string) int {
	fs := e.newFlags("annotate")
	site := fs.String("site", "", "")
	ip := fs.String("ip", "", "")
	devID := fs.Int64("device", 0, "")
	label := fs.String("label", "", "")
	location := fs.String("location", "", "")
	owner := fs.String("owner", "", "")
	notes := fs.String("notes", "", "")
	known := fs.Bool("known", false, "")
	unknown := fs.Bool("unknown", false, "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	s, err := e.openSite(*site)
	if err != nil {
		return e.fail(err)
	}
	defer s.Close()
	if *devID == 0 && *ip != "" {
		latest, err := s.LatestAudit()
		if err != nil {
			return e.fail(err)
		}
		obs, err := s.Observations(latest)
		if err != nil {
			return e.fail(err)
		}
		for _, o := range obs {
			if o.IP == *ip {
				*devID = o.Device.ID
			}
		}
	}
	d, err := s.GetDevice(*devID)
	if *devID == 0 || err != nil {
		fmt.Fprintln(e.stderr, e.T("annotate.not_found"))
		return 1
	}
	// Seules les options données remplacent les valeurs existantes.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	pick := func(name, cur, v string) string {
		if set[name] {
			return v
		}
		return cur
	}
	if err := s.Annotate(d.ID, pick("label", d.Label, *label), pick("location", d.Location, *location),
		pick("owner", d.Owner, *owner), pick("notes", d.Notes, *notes)); err != nil {
		return e.fail(err)
	}
	if *known || *unknown {
		if err := s.SetKnown(d.ID, *known); err != nil {
			return e.fail(err)
		}
	}
	fmt.Fprintln(e.stdout, e.T("annotate.done", "id", strconv.FormatInt(d.ID, 10)))
	return 0
}

// printChanges affiche les changements depuis l'audit précédent.
func printChanges(e *env, w io.Writer, cs []store.Change) {
	if len(cs) == 0 {
		return
	}
	fmt.Fprintln(w, e.T("scan.changes", "count", strconv.Itoa(len(cs))))
	for _, c := range cs {
		line := "  " + e.T("change.icon."+c.Kind) + " " + e.T("change."+c.Kind)
		if c.Field != "" {
			line += " (" + e.T("change.field."+c.Field) + ")"
		}
		who := c.IP
		if c.Label != "" {
			who = c.Label + " " + c.IP
		}
		line += " — " + who
		if c.Port != 0 {
			line += fmt.Sprintf(" %d/%s", c.Port, c.Proto)
		}
		if c.Before != "" || c.After != "" {
			line += " : " + dash(c.Before) + " → " + dash(c.After)
		}
		fmt.Fprintln(w, line)
	}
}
