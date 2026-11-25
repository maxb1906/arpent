package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/maxb1906/arpent/internal/audit"
	"github.com/maxb1906/arpent/internal/config"
	"github.com/maxb1906/arpent/internal/store"
)

func (e *env) dataDir() (string, error) { return config.DataDir(e.data) }

// openSite ouvre le site désigné par --site.
func (e *env) openSite(name string) (*store.Site, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%s", e.T("site.missing"))
	}
	dir, err := e.dataDir()
	if err != nil {
		return nil, err
	}
	return store.OpenSite(dir, name)
}

func cmdSites(e *env, args []string) int {
	fs := e.newFlags("sites")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	dir, err := e.dataDir()
	if err != nil {
		return e.fail(err)
	}
	sites, err := store.ListSites(dir)
	if err != nil {
		return e.fail(err)
	}
	if len(sites) == 0 {
		fmt.Fprintln(e.stdout, e.T("site.none", "dir", dir))
		return 0
	}
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, e.T("col.site")+"\t"+e.T("col.slug")+"\t"+e.T("col.audits")+"\t"+e.T("col.last_audit"))
	for _, s := range sites {
		last := "—"
		if !s.LastAudit.IsZero() {
			last = s.LastAudit.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", s.Name, s.Slug, s.Audits, last)
	}
	tw.Flush()
	return 0
}

func cmdAudits(e *env, args []string) int {
	fs := e.newFlags("audits")
	site := fs.String("site", "", "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	s, err := e.openSite(*site)
	if err != nil {
		return e.fail(err)
	}
	defer s.Close()
	audits, err := s.Audits()
	if err != nil {
		return e.fail(err)
	}
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join([]string{"#", e.T("col.date"), e.T("col.status"), e.T("col.profile"), e.T("col.devices"), e.T("col.open_ports"), e.T("col.technician")}, "\t"))
	for _, a := range audits {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%d\t%s\n", a.ID, a.Started.Local().Format("2006-01-02 15:04"),
			e.T("status."+a.Status), e.T("profile."+a.Profile), a.Devices, a.Ports, dash(a.Technician))
	}
	tw.Flush()
	return 0
}

func cmdShow(e *env, args []string) int {
	fs := e.newFlags("show")
	site := fs.String("site", "", "")
	id := fs.Int64("audit", 0, "")
	if code, ok := e.parse(fs, args); !ok {
		return code
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
			return 0
		}
	}
	a, err := s.GetAudit(*id)
	if err != nil {
		return e.fail(err)
	}
	obs, err := s.Observations(*id)
	if err != nil {
		return e.fail(err)
	}
	fmt.Fprintln(e.stdout, e.T("show.header", "id", strconv.FormatInt(a.ID, 10), "date", a.Started.Local().Format("2006-01-02 15:04"), "profile", e.T("profile."+a.Profile)))
	printObservations(e, e.stdout, obs, a.Finished.Sub(a.Started))
	findings, err := s.Findings(*id)
	if err != nil {
		return e.fail(err)
	}
	printFindings(e, e.stdout, findings)
	if cs, err := s.Changes(*id); err == nil {
		printChanges(e, e.stdout, cs)
	}
	return 0
}

// toObservations convertit un résultat brut (non enregistré) pour l'affichage.
func toObservations(res *audit.Result) []store.Observation {
	out := make([]store.Observation, 0, len(res.Hosts))
	for _, h := range res.Hosts {
		o := store.Observation{IP: h.IP.String(), Vendor: h.Vendor, RandomMAC: h.Random, Names: h.Names, Methods: h.Methods, DeviceType: h.Type, Extra: h.Extra}
		if h.MAC != nil {
			o.MAC = h.MAC.String()
		}
		for _, p := range h.Ports {
			o.Services = append(o.Services, store.Service{Port: p.Port, Proto: p.Proto, Name: p.Service.Name,
				Product: p.Service.Product, Version: p.Service.Version, Banner: p.Service.Banner, Details: p.Service})
		}
		out = append(out, o)
	}
	return out
}

func printObservations(e *env, w io.Writer, obs []store.Observation, took time.Duration) {
	open := 0
	for _, o := range obs {
		fmt.Fprintln(w)
		parts := []string{o.IP}
		if o.MAC != "" {
			parts = append(parts, o.MAC)
		}
		if o.RandomMAC {
			parts = append(parts, e.T("discover.random_mac"))
		} else if o.Vendor != "" {
			parts = append(parts, o.Vendor)
		}
		if o.Device.Label != "" {
			parts = append(parts, "« "+o.Device.Label+" »")
		}
		if len(o.Names) > 0 {
			parts = append(parts, strings.Join(o.Names, ", "))
		}
		if o.DeviceType != "" {
			t := e.T("type." + o.DeviceType)
			if o.Extra.Product != "" {
				t += " · " + o.Extra.Product
			}
			parts = append(parts, "["+t+"]")
		}
		fmt.Fprintln(w, strings.Join(parts, "  "))
		if len(o.Services) == 0 {
			fmt.Fprintln(w, "  "+e.T("scan.no_port"))
		}
		for _, sv := range o.Services {
			open++
			fmt.Fprintf(w, "  %-10s %-12s %s\n", sv.Key(), dash(sv.Name), describe(e, sv.Details))
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, e.T("scan.summary", "hosts", fmt.Sprint(len(obs)), "open", fmt.Sprint(open), "seconds", fmt.Sprintf("%.1f", took.Seconds())))
}

// printFindings affiche les points d'attention, du plus grave au moins grave.
func printFindings(e *env, w io.Writer, fs []store.Finding) {
	c := store.FindingCounts(fs)
	fmt.Fprintln(w, e.T("scan.findings", "critical", fmt.Sprint(c["critical"]), "warning", fmt.Sprint(c["warning"]), "info", fmt.Sprint(c["info"])))
	for _, f := range fs {
		where := f.IP
		if f.Port != 0 {
			where += fmt.Sprintf(" %d/%s", f.Port, f.Proto)
		}
		fmt.Fprintf(w, "  [%s] %s — %s\n", e.T("level."+f.Level), ruleText(e, f, "title"), where)
	}
}

func ruleText(e *env, f store.Finding, part string) string {
	pairs := make([]string, 0, 2*len(f.Params))
	for k, v := range f.Params {
		pairs = append(pairs, k, v)
	}
	return e.T("rule."+f.Rule+"."+part, pairs...)
}
