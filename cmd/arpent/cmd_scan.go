package main

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/maxb1906/arpent/internal/audit"
	"github.com/maxb1906/arpent/internal/engine"
	"github.com/maxb1906/arpent/internal/netinfo"
	"github.com/maxb1906/arpent/internal/portscan"
	"github.com/maxb1906/arpent/internal/probe"
	"github.com/maxb1906/arpent/internal/store"
)

func cmdScan(e *env, args []string) int {
	fs := e.newFlags("scan")
	rng := fs.String("range", "", "")
	profileName := fs.String("profile", "standard", "")
	rate := fs.Int("rate", 0, "")
	noUDP := fs.Bool("no-udp", false, "")
	noDiscover := fs.Bool("no-discover", false, "")
	yes := fs.Bool("yes", false, "")
	site := fs.String("site", "", "")
	technician := fs.String("technician", "", "")
	authorized := fs.Bool("authorized", false, "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	profile, err := portscan.ParseProfile(*profileName)
	if err != nil {
		return e.fail(err)
	}
	if profile == portscan.Full && !*yes && !e.confirm(e.T("ports.full_confirm")) {
		fmt.Fprintln(e.stderr, e.T("cli.aborted"))
		return 1
	}
	targets, err := targetsOrDefault(*rng)
	if err != nil {
		return e.fail(err)
	}
	opt := audit.Options{Targets: targets, Profile: profile, Rate: *rate, NoUDP: *noUDP, NoDiscovery: *noDiscover}
	if *site == "" {
		res, err := runAudit(e, opt, func(o audit.Options) (*audit.Result, error) { return audit.Run(e.ctx, o) })
		if err != nil {
			return e.fail(err)
		}
		printObservations(e, e.stdout, toObservations(res), res.Finished.Sub(res.Started))
		return 0
	}

	// Audit enregistré dans un site.
	dir, err := e.dataDir()
	if err != nil {
		return e.fail(err)
	}
	s, err := store.CreateSite(dir, *site)
	if err != nil {
		return e.fail(err)
	}
	defer s.Close()
	meta := store.AuditMeta{Technician: *technician, Ranges: rangeLabel(*rng, targets), Profile: string(profile), Targets: len(targets)}
	if _, ok := s.Authorized(); !ok {
		// Premier audit du site : confirmation d'autorisation obligatoire (§ 5.8).
		fmt.Fprintln(e.stderr, e.T("legal.warning"))
		if !*authorized && !e.confirm(e.T("legal.confirm", "site", *site)) {
			fmt.Fprintln(e.stderr, e.T("cli.aborted"))
			return 1
		}
		meta.AuthorizedAt, meta.AuthorizedBy = time.Now(), *technician
	}
	id, err := engine.Begin(s, meta)
	if err != nil {
		return e.fail(err)
	}
	res, err := runAudit(e, opt, func(o audit.Options) (*audit.Result, error) { return engine.Run(e.ctx, s, id, o) })
	if err != nil {
		return e.fail(err)
	}
	obs, err := s.Observations(id)
	if err != nil {
		return e.fail(err)
	}
	printObservations(e, e.stdout, obs, res.Finished.Sub(res.Started))
	if findings, err := s.Findings(id); err == nil {
		printFindings(e, e.stdout, findings)
	}
	if cs, err := s.Changes(id); err == nil {
		printChanges(e, e.stdout, cs)
	}
	fmt.Fprintln(e.stdout, e.T("scan.saved", "id", fmt.Sprint(id), "site", s.Slug, "dir", s.Dir))
	return 0
}

// rangeLabel décrit les plages auditées pour l'historique.
func rangeLabel(rng string, targets []netip.Addr) string {
	if rng != "" {
		return rng
	}
	ifs, err := netinfo.Interfaces()
	if err != nil {
		return ""
	}
	var parts []string
	for _, sn := range netinfo.SuggestSubnets(ifs) {
		parts = append(parts, sn.Prefix.String())
	}
	return strings.Join(parts, ", ")
}

// runAudit lance un audit en affichant la progression par phase.
func runAudit(e *env, opt audit.Options, run func(audit.Options) (*audit.Result, error)) (*audit.Result, error) {
	fmt.Fprintln(e.stderr, e.T("scan.running", "count", fmt.Sprint(len(opt.Targets)), "profile", e.T("profile."+string(opt.Profile))))
	var (
		mu  sync.Mutex // les phases appellent Progress depuis plusieurs goroutines
		cur string
		p   *progress
	)
	opt.Progress = func(phase string, done, total int) {
		mu.Lock()
		defer mu.Unlock()
		if phase != cur {
			if p != nil {
				p.done()
			}
			cur = phase
			fmt.Fprintln(e.stderr, e.T("phase."+phase))
			p = newProgress(e)
		}
		p.update(done, total)
	}
	res, err := run(opt)
	if p != nil {
		p.done()
	}
	return res, err
}

// describe résume un service sur une ligne.
func describe(e *env, s probe.Service) string {
	var parts []string
	if s.Product != "" {
		parts = append(parts, strings.TrimSpace(s.Product+" "+s.Version))
	}
	if h := s.HTTP; h != nil {
		if h.Title != "" {
			parts = append(parts, "« "+h.Title+" »")
		}
		parts = append(parts, h.StatusText())
		if h.Location != "" {
			parts = append(parts, "→ "+h.Location)
		}
		if h.AuthRealm != "" {
			parts = append(parts, e.T("scan.auth", "realm", h.AuthRealm))
		}
	}
	if t := s.TLS; t != nil {
		c := e.T("scan.cert", "subject", dash(t.Subject), "until", t.NotAfter.Format("2006-01-02"), "version", t.Version)
		if t.SelfSigned {
			c += " " + e.T("scan.self_signed")
		}
		if time.Now().After(t.NotAfter) {
			c += " " + e.T("scan.expired")
		}
		parts = append(parts, c)
	}
	if len(parts) == 0 && s.Banner != "" {
		b := strings.SplitN(s.Banner, "\n", 2)[0]
		if len(b) > 80 {
			b = b[:80] + "…"
		}
		parts = append(parts, b)
	}
	return strings.Join(parts, " · ")
}
