package audit

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/maxb1906/arpent/internal/discovery"
	"github.com/maxb1906/arpent/internal/fingerprint"
	"github.com/maxb1906/arpent/internal/portscan"
	"github.com/maxb1906/arpent/internal/rawnet"
)

// Modes d'audit (enregistrés et mentionnés dans le rapport).
const (
	ModeStandard = "standard"
	ModeAdvanced = "advanced"
)

// advanced regroupe les poignées brutes ouvertes pour un audit.
type advanced struct {
	links []link
}

type link struct {
	ifc rawnet.Iface
	h   rawnet.Handle
}

// openAdvanced ouvre une poignée par sous-réseau local concerné par les
// cibles ; renvoie nil si le mode avancé est indisponible.
func openAdvanced(targets []netip.Addr) *advanced {
	if !rawnet.Check().Available {
		return nil
	}
	a := &advanced{}
	seen := map[string]bool{}
	for _, t := range targets {
		ifc, err := rawnet.ForPrefix(netip.PrefixFrom(t, 32))
		if err != nil || seen[ifc.Name] {
			continue
		}
		seen[ifc.Name] = true
		h, err := rawnet.Open(ifc)
		if err != nil {
			continue
		}
		a.links = append(a.links, link{ifc, h})
	}
	if len(a.links) == 0 {
		return nil
	}
	return a
}

func (a *advanced) close() {
	for _, l := range a.links {
		l.h.Close()
	}
}

// arpSweep complète les hôtes par une requête ARP brute sur chaque lien.
func (a *advanced) arpSweep(ctx context.Context, targets []netip.Addr, rate int, hosts []discovery.Host) []discovery.Host {
	idx := map[netip.Addr]int{}
	for i, h := range hosts {
		idx[h.IP] = i
	}
	for _, l := range a.links {
		for ip, mac := range rawnet.ARPSweep(ctx, l.h, l.ifc, targets, rate, 1500*time.Millisecond) {
			if i, ok := idx[ip]; ok {
				hosts[i].Methods = appendName(hosts[i].Methods, "arp-raw")
				if hosts[i].MAC == nil {
					hosts[i].MAC = mac
				}
				continue
			}
			idx[ip] = len(hosts)
			hosts = append(hosts, discovery.Host{IP: ip, MAC: mac, Methods: []string{"arp-raw"}})
		}
	}
	return finishHosts(hosts)
}

// listen écoute passivement tous les liens pendant d.
func (a *advanced) listen(ctx context.Context, d time.Duration) []rawnet.Seen {
	out := make(chan []rawnet.Seen, len(a.links))
	for _, l := range a.links {
		go func(l link) { out <- rawnet.Listen(ctx, l.h, l.ifc, d) }(l)
	}
	var all []rawnet.Seen
	for range a.links {
		all = append(all, <-out...)
	}
	return all
}

// mergeSeen ajoute les appareils repérés passivement (dans les cibles).
func mergeSeen(hosts []discovery.Host, seen []rawnet.Seen, targets []netip.Addr) []discovery.Host {
	want := map[netip.Addr]bool{}
	for _, t := range targets {
		want[t] = true
	}
	idx := map[netip.Addr]int{}
	for i, h := range hosts {
		idx[h.IP] = i
	}
	for _, s := range seen {
		if !s.IP.IsValid() || !want[s.IP] {
			continue
		}
		i, ok := idx[s.IP]
		if !ok {
			i = len(hosts)
			idx[s.IP] = i
			hosts = append(hosts, discovery.Host{IP: s.IP})
		}
		h := &hosts[i]
		h.Methods = appendName(h.Methods, "passive")
		if h.MAC == nil && s.MAC != nil {
			h.MAC = s.MAC
		}
		if s.Hostname != "" {
			h.Names = appendName(h.Names, s.Hostname)
		}
	}
	return finishHosts(hosts)
}

func sortHosts(h []discovery.Host) {
	sort.Slice(h, func(i, j int) bool { return h[i].IP.Less(h[j].IP) })
}

// finishHosts recalcule fabricant et MAC aléatoire, et trie par adresse.
func finishHosts(hosts []discovery.Host) []discovery.Host {
	for i := range hosts {
		if hosts[i].MAC != nil {
			hosts[i].Random = fingerprint.LocallyAdministered(hosts[i].MAC)
			hosts[i].Vendor = fingerprint.Vendor(hosts[i].MAC)
		}
	}
	sortHosts(hosts)
	return hosts
}

// synScan scanne en SYN les hôtes du sous-réseau local dont la MAC est
// connue ; renvoie les ports ouverts, les hôtes à scanner en « connect » et
// ceux déjà couverts par le SYN (pour l'UDP).
func (a *advanced) synScan(ctx context.Context, hosts []discovery.Host, ports []int, rate int, progress func(int, int)) ([]portscan.Result, []netip.Addr, []netip.Addr) {
	if rate <= 0 {
		rate = 1000
	}
	var connect, syn []netip.Addr
	var out []portscan.Result
	for _, l := range a.links {
		macs := map[netip.Addr]net.HardwareAddr{}
		for _, h := range hosts {
			if h.MAC != nil && l.ifc.Prefix.Contains(h.IP) && h.IP != l.ifc.IP {
				macs[h.IP] = h.MAC
			}
		}
		for _, o := range rawnet.SYNScan(ctx, l.h, l.ifc, macs, ports, rate, 2*time.Second, progress) {
			out = append(out, portscan.Result{IP: o.IP, Port: o.Port, Proto: "tcp"})
		}
		for ip := range macs {
			syn = append(syn, ip)
		}
	}
	inSyn := map[netip.Addr]bool{}
	for _, ip := range syn {
		inSyn[ip] = true
	}
	for _, h := range hosts {
		if !inSyn[h.IP] {
			connect = append(connect, h.IP)
		}
	}
	return out, connect, syn
}
