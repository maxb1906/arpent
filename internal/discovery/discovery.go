// Package discovery trouve les appareils actifs d'une liste d'adresses sans
// droits administrateur : sondes « réveil » (ICMP si autorisé, connexions
// TCP légères, ARP actif sous Windows), lecture de la table ARP de l'OS,
// fabricant via la base OUI et noms par DNS inverse.
package discovery

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maxb1906/arpent/internal/fingerprint"
	"github.com/maxb1906/arpent/internal/netinfo"
	"github.com/maxb1906/arpent/internal/pace"
)

// Méthodes de détection d'un hôte.
const (
	MethodICMP     = "icmp"
	MethodTCP      = "tcp"
	MethodARP      = "arp"       // réponse à une requête ARP active (SendARP)
	MethodARPTable = "arp-table" // présent dans la table ARP de l'OS
)

// WakePorts sont les ports TCP essayés pour réveiller un hôte : une réponse,
// même un refus de connexion, prouve que l'hôte existe.
var WakePorts = []int{80, 443, 445, 22, 139, 135, 3389, 8080, 62078, 554, 9100, 5000}

// Options règle la découverte.
type Options struct {
	Concurrency int           // hôtes sondés en parallèle (défaut 64)
	Rate        int           // sondes par seconde au maximum (défaut 300, ≤ 0 : défaut)
	Timeout     time.Duration // délai par sonde (défaut 1,5 s)
	Ports       []int         // ports TCP de réveil (défaut WakePorts)
	NoICMP      bool
	NoActiveARP bool
	NoDNS       bool
	// Local liste les sous-réseaux directement connectés : MAC et ARP n'ont
	// de sens que pour eux. Vide : déduit des interfaces de la machine.
	Local []netip.Prefix
	// Progress est appelé après chaque hôte sondé (peut être nil).
	Progress func(done, total int)
}

func (o *Options) defaults() {
	if o.Concurrency <= 0 {
		o.Concurrency = 64
	}
	if o.Rate <= 0 {
		o.Rate = 300
	}
	if o.Timeout <= 0 {
		o.Timeout = 1500 * time.Millisecond
	}
	if o.Ports == nil {
		o.Ports = WakePorts
	}
	if o.Local == nil {
		if ifs, err := netinfo.Interfaces(); err == nil {
			for _, i := range ifs {
				if i.Up {
					o.Local = append(o.Local, i.Prefixes...)
				}
			}
		}
	}
}

// Host est un appareil trouvé.
type Host struct {
	IP      netip.Addr
	MAC     net.HardwareAddr
	Vendor  string
	Random  bool     // MAC administrée localement (aléatoire)
	Names   []string // noms DNS inverses
	Methods []string // comment l'hôte a été détecté
	RTT     time.Duration
}

// Run sonde targets et renvoie les hôtes trouvés, triés par adresse.
func Run(ctx context.Context, targets []netip.Addr, opt Options) ([]Host, error) {
	opt.defaults()
	lim := pace.New(opt.Rate)
	isLocal := func(a netip.Addr) bool {
		for _, p := range opt.Local {
			if p.Masked().Contains(a) {
				return true
			}
		}
		return false
	}
	icmpOK := !opt.NoICMP && pingAvailable()
	arpOK := !opt.NoActiveARP && netinfo.ActiveARPSupported()

	var (
		mu    sync.Mutex
		hosts = map[netip.Addr]*Host{}
		done  atomic.Int64
		wg    sync.WaitGroup
	)
	mark := func(ip netip.Addr, method string, mac net.HardwareAddr, rtt time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		h := hosts[ip]
		if h == nil {
			h = &Host{IP: ip}
			hosts[ip] = h
		}
		h.Methods = appendUnique(h.Methods, method)
		if mac != nil && h.MAC == nil {
			h.MAC = mac
		}
		if rtt > 0 && (h.RTT == 0 || rtt < h.RTT) {
			h.RTT = rtt
		}
	}

	ch := make(chan netip.Addr)
	for w := 0; w < opt.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ch {
				probeHost(ctx, ip, opt, lim, icmpOK, arpOK && isLocal(ip), mark)
				if opt.Progress != nil {
					opt.Progress(int(done.Add(1)), len(targets))
				}
			}
		}()
	}
feed:
	for _, t := range targets {
		select {
		case ch <- t:
		case <-ctx.Done():
			break feed
		}
	}
	close(ch)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Les sondes ont rempli la table ARP de l'OS : on la relit.
	wanted := make(map[netip.Addr]bool, len(targets))
	for _, t := range targets {
		wanted[t] = true
	}
	if table, err := netinfo.ARPTable(); err == nil {
		for _, n := range table {
			if wanted[n.IP] && isLocal(n.IP) {
				mark(n.IP, MethodARPTable, n.MAC, 0)
			}
		}
	}

	out := make([]Host, 0, len(hosts))
	for _, h := range hosts {
		if h.MAC != nil {
			h.Random = fingerprint.LocallyAdministered(h.MAC)
			h.Vendor = fingerprint.Vendor(h.MAC)
		}
		out = append(out, *h)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].IP.Less(out[b].IP) })

	if !opt.NoDNS {
		resolveNames(ctx, out, opt.Concurrency)
	}
	return out, nil
}

func probeHost(ctx context.Context, ip netip.Addr, opt Options, lim *pace.Limiter, icmpOK, arpOK bool,
	mark func(netip.Addr, string, net.HardwareAddr, time.Duration)) {
	if arpOK {
		if lim.Wait(ctx) != nil {
			return
		}
		c, cancel := context.WithTimeout(ctx, 2*opt.Timeout)
		mac, err := netinfo.ActiveARP(c, ip)
		cancel()
		if err == nil {
			mark(ip, MethodARP, mac, 0)
		}
	}
	if icmpOK {
		if lim.Wait(ctx) != nil {
			return
		}
		if rtt, ok := ping(ctx, ip, opt.Timeout); ok {
			mark(ip, MethodICMP, nil, rtt)
			return
		}
	}
	// Réveil TCP : on s'arrête au premier signe de vie.
	for _, port := range opt.Ports {
		if lim.Wait(ctx) != nil {
			return
		}
		if rtt, alive := tcpAlive(ctx, ip, port, opt.Timeout); alive {
			mark(ip, MethodTCP, nil, rtt)
			return
		}
	}
}

// tcpAlive tente une connexion : acceptée ou refusée, l'hôte répond.
func tcpAlive(ctx context.Context, ip netip.Addr, port int, timeout time.Duration) (time.Duration, bool) {
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, uint16(port)).String())
	rtt := time.Since(start)
	if err == nil {
		c.Close()
		return rtt, true
	}
	return rtt, isRefused(err)
}

func resolveNames(ctx context.Context, hosts []Host, workers int) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h *Host) {
			defer wg.Done()
			defer func() { <-sem }()
			c, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(c, h.IP.String())
			if err != nil {
				return
			}
			for _, n := range names {
				if n = trimDot(n); n != "" {
					h.Names = appendUnique(h.Names, n)
				}
			}
		}(&hosts[i])
	}
	wg.Wait()
}

func trimDot(s string) string {
	for len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
