package main

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/maxb1906/arpent/internal/discovery"
	"github.com/maxb1906/arpent/internal/fingerprint"
)

func cmdDiscover(e *env, args []string) int {
	fs := e.newFlags("discover")
	rng := fs.String("range", "", "")
	rate := fs.Int("rate", 300, "")
	noPing := fs.Bool("no-ping", false, "")
	noDNS := fs.Bool("no-dns", false, "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	targets, err := targetsOrDefault(*rng)
	if err != nil {
		return e.fail(err)
	}
	if len(targets) == 0 {
		fmt.Fprintln(e.stderr, e.T("netinfo.no_subnet"))
		return 1
	}
	fmt.Fprintln(e.stderr, e.T("discover.running", "count", fmt.Sprint(len(targets))))
	start := time.Now()
	prog := newProgress(e)
	hosts, err := discovery.Run(e.ctx, targets, discovery.Options{
		Rate:     *rate,
		NoICMP:   *noPing,
		NoDNS:    *noDNS,
		Progress: prog.update,
	})
	prog.done()
	if err != nil {
		return e.fail(err)
	}

	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join([]string{e.T("col.ip"), e.T("col.mac"), e.T("col.vendor"), e.T("col.name"), e.T("col.methods")}, "\t"))
	for _, h := range hosts {
		vendor := h.Vendor
		if h.Random {
			vendor = e.T("discover.random_mac")
		}
		mac := ""
		if h.MAC != nil {
			mac = h.MAC.String()
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", h.IP, dash(mac), dash(vendor), dash(strings.Join(h.Names, ", ")), strings.Join(h.Methods, ","))
	}
	tw.Flush()
	fmt.Fprintln(e.stdout, e.T("discover.summary", "count", fmt.Sprint(len(hosts)), "seconds", fmt.Sprintf("%.1f", time.Since(start).Seconds()), "oui", fmt.Sprint(fingerprint.OUICount())))
	return 0
}
