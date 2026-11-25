package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/maxb1906/arpent/internal/discovery"
	"github.com/maxb1906/arpent/internal/portscan"
)

func cmdPorts(e *env, args []string) int {
	fs := e.newFlags("ports")
	rng := fs.String("range", "", "")
	profileName := fs.String("profile", "standard", "")
	rate := fs.Int("rate", 500, "")
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

	hosts := targets
	if !*noDiscover {
		fmt.Fprintln(e.stderr, e.T("discover.running", "count", fmt.Sprint(len(targets))))
		p := newProgress(e)
		found, err := discovery.Run(e.ctx, targets, discovery.Options{NoDNS: true, Progress: p.update})
		p.done()
		if err != nil {
			return e.fail(err)
		}
		hosts = hosts[:0:0]
		for _, h := range found {
			hosts = append(hosts, h.IP)
		}
	}
	if len(hosts) == 0 {
		fmt.Fprintln(e.stdout, e.T("ports.no_host"))
		return 0
	}

	opt := portscan.Options{Ports: profile.Ports(), Rate: *rate}
	if !*noUDP {
		opt.UDP = portscan.DefaultUDPProbes
	}
	fmt.Fprintln(e.stderr, e.T("ports.running", "hosts", fmt.Sprint(len(hosts)), "ports", fmt.Sprint(len(opt.Ports)), "profile", e.T("profile."+string(profile))))
	start := time.Now()
	p := newProgress(e)
	opt.Progress = p.update
	res, err := portscan.Scan(e.ctx, hosts, opt)
	p.done()
	if err != nil {
		return e.fail(err)
	}

	byHost := map[netip.Addr][]string{}
	for _, r := range res {
		name := r.Service
		if name == "" && r.Proto == "tcp" {
			name = portscan.ServiceName(r.Port)
		}
		s := fmt.Sprintf("%d/%s", r.Port, r.Proto)
		if name != "" {
			s += " (" + name + ")"
		}
		byHost[r.IP] = append(byHost[r.IP], s)
	}
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, e.T("col.ip")+"\t"+e.T("col.open_ports"))
	for _, h := range hosts {
		fmt.Fprintf(tw, "%s\t%s\n", h, dash(strings.Join(byHost[h], ", ")))
	}
	tw.Flush()
	fmt.Fprintln(e.stdout, e.T("ports.summary", "open", fmt.Sprint(len(res)), "hosts", fmt.Sprint(len(hosts)), "seconds", fmt.Sprintf("%.1f", time.Since(start).Seconds())))
	return 0
}

// confirm pose une question oui/non sur stdin ; non par défaut.
func (e *env) confirm(question string) bool {
	fmt.Fprint(e.stderr, question+" "+e.T("cli.yes_no")+" ")
	line, _ := bufio.NewReader(e.stdin).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "o" || a == "oui" || a == "y" || a == "yes"
}
