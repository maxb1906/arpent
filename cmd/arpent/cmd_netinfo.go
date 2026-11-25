package main

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/maxb1906/arpent/internal/netinfo"
)

func cmdInterfaces(e *env, args []string) int {
	fs := e.newFlags("interfaces")
	all := fs.Bool("all", false, "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	ifs, err := netinfo.Interfaces()
	if err != nil {
		return e.fail(err)
	}
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, e.T("col.interface")+"\t"+e.T("col.state")+"\t"+e.T("col.mac")+"\t"+e.T("col.ipv4"))
	for _, i := range ifs {
		if !*all && (!i.Up || len(i.Prefixes) == 0) {
			continue
		}
		state := e.T("state.down")
		if i.Up {
			state = e.T("state.up")
		}
		var ps []string
		for _, p := range i.Prefixes {
			ps = append(ps, p.String())
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", i.Name, state, dash(i.MAC.String()), dash(strings.Join(ps, ", ")))
	}
	tw.Flush()

	fmt.Fprintln(e.stdout)
	subnets := netinfo.SuggestSubnets(ifs)
	if len(subnets) == 0 {
		fmt.Fprintln(e.stdout, e.T("netinfo.no_subnet"))
		return 0
	}
	fmt.Fprintln(e.stdout, e.T("netinfo.suggested"))
	for _, s := range subnets {
		line := "  " + e.T("netinfo.subnet_line", "prefix", s.Prefix.String(), "interface", s.Interface, "address", s.Address.String())
		if s.Reduced {
			line += " " + e.T("netinfo.reduced")
		}
		fmt.Fprintln(e.stdout, line)
	}
	return 0
}

func cmdARP(e *env, args []string) int {
	fs := e.newFlags("arp")
	active := fs.Bool("active", false, "")
	rng := fs.String("range", "", "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}

	neighbors := map[netip.Addr]netinfo.Neighbor{}
	if *active {
		if !netinfo.ActiveARPSupported() {
			fmt.Fprintln(e.stderr, e.T("arp.active_unsupported"))
		} else {
			targets, err := targetsOrDefault(*rng)
			if err != nil {
				return e.fail(err)
			}
			fmt.Fprintln(e.stderr, e.T("arp.active_running", "count", fmt.Sprint(len(targets))))
			for _, n := range activeSweep(e.ctx, targets, 64) {
				neighbors[n.IP] = n
			}
		}
	}
	table, err := netinfo.ARPTable()
	if err != nil {
		return e.fail(err)
	}
	for _, n := range table {
		if _, ok := neighbors[n.IP]; !ok {
			neighbors[n.IP] = n
		}
	}

	list := make([]netinfo.Neighbor, 0, len(neighbors))
	for _, n := range neighbors {
		list = append(list, n)
	}
	sort.Slice(list, func(a, b int) bool { return list[a].IP.Less(list[b].IP) })
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, e.T("col.ip")+"\t"+e.T("col.mac")+"\t"+e.T("col.interface"))
	for _, n := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", n.IP, n.MAC, dash(n.Interface))
	}
	tw.Flush()
	fmt.Fprintln(e.stdout, e.T("arp.count", "count", fmt.Sprint(len(list))))
	return 0
}

// targetsOrDefault renvoie les adresses de rng, ou celles des sous-réseaux
// proposés si rng est vide.
func targetsOrDefault(rng string) ([]netip.Addr, error) {
	if rng != "" {
		return netinfo.ParseRanges(rng)
	}
	ifs, err := netinfo.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, s := range netinfo.SuggestSubnets(ifs) {
		out = append(out, netinfo.Hosts(s.Prefix)...)
	}
	return out, nil
}

// activeSweep interroge chaque adresse avec SendARP, workers en parallèle.
func activeSweep(ctx context.Context, targets []netip.Addr, workers int) []netinfo.Neighbor {
	var (
		mu  sync.Mutex
		out []netinfo.Neighbor
		wg  sync.WaitGroup
	)
	ch := make(chan netip.Addr)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ch {
				c, cancel := context.WithTimeout(ctx, 3*time.Second)
				mac, err := netinfo.ActiveARP(c, ip)
				cancel()
				if err == nil {
					mu.Lock()
					out = append(out, netinfo.Neighbor{IP: ip, MAC: mac})
					mu.Unlock()
				}
			}
		}()
	}
	for _, t := range targets {
		select {
		case ch <- t:
		case <-ctx.Done():
		}
	}
	close(ch)
	wg.Wait()
	return out
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
