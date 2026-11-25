package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/maxb1906/arpent/internal/audit"
	"github.com/maxb1906/arpent/internal/portscan"
	"github.com/maxb1906/arpent/internal/probe"
)

func cmdScan(e *env, args []string) int {
	fs := e.newFlags("scan")
	rng := fs.String("range", "", "")
	profileName := fs.String("profile", "standard", "")
	rate := fs.Int("rate", 0, "")
	noUDP := fs.Bool("no-udp", false, "")
	noDiscover := fs.Bool("no-discover", false, "")
	yes := fs.Bool("yes", false, "")
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
	res, err := runAudit(e, audit.Options{Targets: targets, Profile: profile, Rate: *rate, NoUDP: *noUDP, NoDiscovery: *noDiscover})
	if err != nil {
		return e.fail(err)
	}
	printAudit(e, e.stdout, res)
	return 0
}

// runAudit lance un audit en affichant la progression par phase.
func runAudit(e *env, opt audit.Options) (*audit.Result, error) {
	fmt.Fprintln(e.stderr, e.T("scan.running", "count", fmt.Sprint(len(opt.Targets)), "profile", e.T("profile."+string(opt.Profile))))
	var cur string
	var p *progress
	opt.Progress = func(phase string, done, total int) {
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
	res, err := audit.Run(e.ctx, opt)
	if p != nil {
		p.done()
	}
	return res, err
}

func printAudit(e *env, w io.Writer, res *audit.Result) {
	open := 0
	for _, h := range res.Hosts {
		fmt.Fprintln(w)
		line := h.IP.String()
		if h.MAC != nil {
			line += "  " + h.MAC.String()
		}
		if h.Random {
			line += "  " + e.T("discover.random_mac")
		} else if h.Vendor != "" {
			line += "  " + h.Vendor
		}
		if len(h.Names) > 0 {
			line += "  " + strings.Join(h.Names, ", ")
		}
		fmt.Fprintln(w, line)
		if len(h.Ports) == 0 {
			fmt.Fprintln(w, "  "+e.T("scan.no_port"))
		}
		for _, p := range h.Ports {
			open++
			fmt.Fprintf(w, "  %-10s %-12s %s\n", fmt.Sprintf("%d/%s", p.Port, p.Proto), dash(p.Service.Name), describe(e, p.Service))
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, e.T("scan.summary", "hosts", fmt.Sprint(len(res.Hosts)), "open", fmt.Sprint(open),
		"seconds", fmt.Sprintf("%.1f", res.Finished.Sub(res.Started).Seconds())))
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
