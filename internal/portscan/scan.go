// Package portscan scanne les ports TCP (connexion complète, sans droits
// administrateur) et quelques services UDP ciblés, avec limitation du débit
// et du nombre de connexions simultanées, globalement et par hôte.
package portscan

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maxb1906/arpent/internal/pace"
)

// Options règle le scan.
type Options struct {
	Ports       []int         // ports TCP (défaut : profil standard)
	UDP         []UDPProbe    // sondes UDP (nil : aucune ; voir DefaultUDPProbes)
	Concurrency int           // connexions simultanées au total (défaut 256)
	PerHost     int           // connexions simultanées par hôte (défaut 16)
	Rate        int           // connexions par seconde au total (défaut 500)
	Timeout     time.Duration // délai de connexion (défaut 1 s)
	UDPTimeout  time.Duration // attente d'une réponse UDP (défaut 1,5 s)
	Progress    func(done, total int)
}

func (o *Options) defaults() {
	if o.Ports == nil {
		o.Ports = Standard.Ports()
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 256
	}
	if o.PerHost <= 0 {
		o.PerHost = 16
	}
	if o.Rate <= 0 {
		o.Rate = 500
	}
	if o.Timeout <= 0 {
		o.Timeout = time.Second
	}
	if o.UDPTimeout <= 0 {
		o.UDPTimeout = 1500 * time.Millisecond
	}
}

// Result est un port ouvert.
type Result struct {
	IP       netip.Addr
	Port     int
	Proto    string // "tcp" ou "udp"
	Service  string // service présumé (UDP : celui de la sonde)
	RTT      time.Duration
	Response []byte // réponse brute (UDP)
}

type task struct {
	ip  netip.Addr
	tcp int
	udp *UDPProbe
}

// Scan renvoie les ports ouverts des hôtes, triés par hôte, protocole, port.
func Scan(ctx context.Context, hosts []netip.Addr, opt Options) ([]Result, error) {
	opt.defaults()
	lim := pace.New(opt.Rate)

	perHost := make(map[netip.Addr]chan struct{}, len(hosts))
	for _, h := range hosts {
		perHost[h] = make(chan struct{}, opt.PerHost)
	}
	total := len(hosts) * (len(opt.Ports) + len(opt.UDP))

	var (
		mu   sync.Mutex
		out  []Result
		done atomic.Int64
		wg   sync.WaitGroup
	)
	tasks := make(chan task)
	for w := 0; w < opt.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				slot := perHost[t.ip]
				select {
				case slot <- struct{}{}:
				case <-ctx.Done():
					continue
				}
				var r *Result
				if lim.Wait(ctx) == nil {
					if t.udp != nil {
						r = probeUDP(ctx, t.ip, *t.udp, opt.UDPTimeout)
					} else {
						r = probeTCP(ctx, t.ip, t.tcp, opt.Timeout)
					}
				}
				<-slot
				if r != nil {
					mu.Lock()
					out = append(out, *r)
					mu.Unlock()
				}
				if opt.Progress != nil {
					opt.Progress(int(done.Add(1)), total)
				}
			}
		}()
	}

	// Port par port sur tous les hôtes : la charge est répartie au lieu de
	// s'abattre sur un seul appareil à la fois.
	func() {
		send := func(t task) bool {
			select {
			case tasks <- t:
				return true
			case <-ctx.Done():
				return false
			}
		}
		for i := range opt.UDP {
			for _, h := range hosts {
				if !send(task{ip: h, udp: &opt.UDP[i]}) {
					return
				}
			}
		}
		for _, p := range opt.Ports {
			for _, h := range hosts {
				if !send(task{ip: h, tcp: p}) {
					return
				}
			}
		}
	}()
	close(tasks)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	SortResults(out)
	return out, nil
}

// SortResults trie les résultats par hôte, protocole, port.
func SortResults(out []Result) {
	sort.Slice(out, func(a, b int) bool {
		x, y := out[a], out[b]
		if x.IP != y.IP {
			return x.IP.Less(y.IP)
		}
		if x.Proto != y.Proto {
			return x.Proto < y.Proto
		}
		return x.Port < y.Port
	})
}

func probeTCP(ctx context.Context, ip netip.Addr, port int, timeout time.Duration) *Result {
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, uint16(port)).String())
	if err != nil {
		return nil
	}
	rtt := time.Since(start)
	c.Close()
	return &Result{IP: ip, Port: port, Proto: "tcp", RTT: rtt}
}

func probeUDP(ctx context.Context, ip netip.Addr, p UDPProbe, timeout time.Duration) *Result {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "udp", netip.AddrPortFrom(ip, uint16(p.Port)).String())
	if err != nil {
		return nil
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	c.SetDeadline(deadline)
	start := time.Now()
	if _, err := c.Write(p.Payload); err != nil {
		return nil
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil || n == 0 {
		return nil // pas de réponse, ou ICMP « port inaccessible »
	}
	return &Result{IP: ip, Port: p.Port, Proto: "udp", Service: p.Service, RTT: time.Since(start), Response: append([]byte(nil), buf[:n]...)}
}
