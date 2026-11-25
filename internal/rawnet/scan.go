package rawnet

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/maxb1906/arpent/internal/pace"
)

// ARPSweep envoie une requête ARP brute à chaque cible du sous-réseau local
// et renvoie les adresses MAC des appareils qui répondent, même silencieux
// en ICMP et en TCP.
func ARPSweep(ctx context.Context, h Handle, ifc Iface, targets []netip.Addr, rate int, wait time.Duration) map[netip.Addr]net.HardwareAddr {
	want := map[netip.Addr]bool{}
	for _, t := range targets {
		if ifc.Prefix.Contains(t) && t != ifc.IP {
			want[t] = true
		}
	}
	out := map[netip.Addr]net.HardwareAddr{}
	var mu sync.Mutex
	done := make(chan struct{})
	stopRead := make(chan time.Time, 1)
	go func() {
		defer close(done)
		until := time.Now().Add(24 * time.Hour)
		for ctx.Err() == nil {
			select {
			case u := <-stopRead:
				until = u
			default:
			}
			if time.Now().After(until) {
				return
			}
			f, err := h.ReadPacket(200 * time.Millisecond)
			if err != nil {
				if err == ErrTimeout {
					continue
				}
				return
			}
			if ip, mac, op, ok := ARPSender(f); ok && op == 2 && want[ip] && !bytes.Equal(mac, ifc.MAC) {
				mu.Lock()
				out[ip] = mac
				mu.Unlock()
			}
		}
	}()
	lim := pace.New(rate)
	for t := range want {
		if lim.Wait(ctx) != nil {
			break
		}
		h.WritePacket(ARPRequest(ifc, t))
	}
	stopRead <- time.Now().Add(wait)
	<-done
	return out
}

// OpenPort est un port ouvert trouvé par le scan SYN.
type OpenPort struct {
	IP   netip.Addr
	Port int
}

// SYNScan envoie un SYN à chaque (hôte, port) et classe les réponses :
// SYN-ACK = ouvert. Le système répond lui-même RST aux SYN-ACK (aucune
// connexion n'est établie). dstMAC donne l'adresse MAC de chaque hôte
// (sous-réseau local) ; les hôtes sans MAC sont ignorés.
func SYNScan(ctx context.Context, h Handle, ifc Iface, dstMAC map[netip.Addr]net.HardwareAddr, ports []int, rate int, wait time.Duration,
	progress func(done, total int)) []OpenPort {
	var rb [6]byte
	rand.Read(rb[:])
	srcPort := uint16(40000 + binary.BigEndian.Uint16(rb[:2])%20000)
	seq := binary.BigEndian.Uint32(rb[2:])

	found := map[OpenPort]bool{}
	var mu sync.Mutex
	done := make(chan struct{})
	stopAt := make(chan time.Time, 1)
	go func() {
		defer close(done)
		until := time.Now().Add(24 * time.Hour)
		for ctx.Err() == nil {
			select {
			case u := <-stopAt:
				until = u
			default:
			}
			if time.Now().After(until) {
				return
			}
			f, err := h.ReadPacket(200 * time.Millisecond)
			if err != nil {
				if err == ErrTimeout {
					continue
				}
				return
			}
			r, ok := ParseTCPReply(f, ifc.IP)
			if !ok || r.ToPort != srcPort || r.Ack != seq+1 || !r.SYNACK {
				continue
			}
			if _, known := dstMAC[r.From]; known {
				mu.Lock()
				found[OpenPort{r.From, int(r.Port)}] = true
				mu.Unlock()
			}
		}
	}()
	hosts := make([]netip.Addr, 0, len(dstMAC))
	for ip := range dstMAC {
		hosts = append(hosts, ip)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Less(hosts[j]) })
	total, n := len(hosts)*len(ports), 0
	lim := pace.New(rate)
send:
	for _, p := range ports { // port par port : la charge est étalée
		for _, ip := range hosts {
			if lim.Wait(ctx) != nil {
				break send
			}
			h.WritePacket(SYN(ifc, dstMAC[ip], ip, srcPort, uint16(p), seq))
			n++
			if progress != nil && n%64 == 0 {
				progress(n, total)
			}
		}
	}
	if progress != nil {
		progress(total, total)
	}
	stopAt <- time.Now().Add(wait)
	<-done
	out := make([]OpenPort, 0, len(found))
	for o := range found {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP.Less(out[j].IP)
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// Seen est un appareil repéré par l'écoute passive.
type Seen struct {
	IP       netip.Addr
	MAC      net.HardwareAddr
	Hostname string
	Vendor   string // classe DHCP
	Sources  []string
}

// Listen écoute le réseau pendant d (ARP, DHCP, mDNS) sans rien envoyer,
// pour repérer les appareils discrets.
func Listen(ctx context.Context, h Handle, ifc Iface, d time.Duration) []Seen {
	byMAC := map[string]*Seen{}
	byIP := map[netip.Addr]*Seen{}
	get := func(ip netip.Addr, mac net.HardwareAddr) *Seen {
		var s *Seen
		if mac != nil {
			s = byMAC[mac.String()]
		}
		if s == nil && ip.IsValid() {
			s = byIP[ip]
		}
		if s == nil {
			s = &Seen{}
		}
		if mac != nil && s.MAC == nil {
			s.MAC = mac
			byMAC[mac.String()] = s
		}
		if ip.IsValid() && !s.IP.IsValid() {
			s.IP = ip
			byIP[ip] = s
		}
		return s
	}
	src := func(s *Seen, name string) {
		for _, x := range s.Sources {
			if x == name {
				return
			}
		}
		s.Sources = append(s.Sources, name)
	}
	readLoop(ctx, h, time.Now().Add(d), func(f []byte) {
		if len(f) >= 12 && bytes.Equal(f[6:12], ifc.MAC) {
			return // nos propres trames
		}
		if ip, mac, _, ok := ARPSender(f); ok && ifc.Prefix.Contains(ip) {
			src(get(ip, mac), "arp")
			return
		}
		if di, ok := ParseDHCP(f); ok {
			s := get(di.IP, di.MAC)
			if di.Hostname != "" {
				s.Hostname = di.Hostname
			}
			if di.Vendor != "" {
				s.Vendor = di.Vendor
			}
			src(s, "dhcp")
			return
		}
		if m, ok := MDNSHost(f); ok {
			for ip, name := range m {
				if ifc.Prefix.Contains(ip) {
					s := get(ip, nil)
					if s.Hostname == "" {
						s.Hostname = name
					}
					src(s, "mdns")
				}
			}
		}
	})
	var out []Seen
	seen := map[*Seen]bool{}
	for _, s := range byMAC {
		seen[s] = true
		out = append(out, *s)
	}
	for _, s := range byIP {
		if !seen[s] {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out
}
