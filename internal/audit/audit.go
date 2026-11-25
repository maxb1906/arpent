// Package audit enchaîne les phases d'un audit : découverte des appareils,
// scan des ports, puis identification des services. Il ne fait qu'orchestrer
// les paquets discovery, portscan et probe ; le stockage est ailleurs.
package audit

import (
	"context"
	"net/netip"
	"time"

	"github.com/maxb1906/arpent/internal/discovery"
	"github.com/maxb1906/arpent/internal/fingerprint"
	"github.com/maxb1906/arpent/internal/portscan"
	"github.com/maxb1906/arpent/internal/probe"
	"github.com/maxb1906/arpent/internal/rawnet"
)

// Phases d'un audit, dans l'ordre.
const (
	PhaseDiscovery = "discovery"
	PhasePorts     = "ports"
	PhaseProbes    = "probes"
	PhaseEnrich    = "enrich"
	PhasePassive   = "passive"
)

// Options règle un audit.
type Options struct {
	Targets     []netip.Addr
	Profile     portscan.Profile
	Rate        int  // sondes par seconde (défaut 300 découverte, 500 ports)
	NoUDP       bool // pas de sondes UDP
	NoDiscovery bool // scanner toutes les cibles sans découverte préalable
	NoDNS       bool
	// Advanced demande le mode avancé (Npcap + administrateur, ou root) :
	// ARP brut, scan SYN du sous-réseau local, écoute passive pendant Passive.
	// S'il est indisponible, l'audit se fait en mode standard.
	Advanced bool
	Passive  time.Duration
	// Progress est appelé pendant chaque phase (peut être nil).
	Progress func(phase string, done, total int)
}

// Port est un port ouvert et ce qui y a été identifié.
type Port struct {
	Port     int           `json:"port"`
	Proto    string        `json:"proto"`
	Service  probe.Service `json:"service"`
	Response []byte        `json:"-"` // réponse UDP brute
}

// Host est un appareil et ses ports ouverts.
type Host struct {
	discovery.Host
	Ports []Port
	Extra Extra
	Type  string // type d'appareil deviné (fingerprint.Types)
}

// Result est le résultat brut d'un audit.
type Result struct {
	Started  time.Time
	Finished time.Time
	Profile  portscan.Profile
	Targets  int
	Hosts    []Host
	Mode     string // standard ou advanced (mode réellement utilisé)
}

// testPorts remplace la liste du profil dans les tests.
var testPorts []int

// SetTestPorts impose la liste de ports (tests d'autres paquets) ; nil rétablit.
func SetTestPorts(p []int) { testPorts = p }

// Run exécute l'audit complet.
func Run(ctx context.Context, opt Options) (*Result, error) {
	if opt.Profile == "" {
		opt.Profile = portscan.Standard
	}
	progress := func(phase string) func(int, int) {
		if opt.Progress == nil {
			return nil
		}
		return func(d, t int) { opt.Progress(phase, d, t) }
	}
	res := &Result{Started: time.Now(), Profile: opt.Profile, Targets: len(opt.Targets), Mode: ModeStandard}
	var adv *advanced
	if opt.Advanced {
		if adv = openAdvanced(opt.Targets); adv != nil {
			defer adv.close()
			res.Mode = ModeAdvanced
		}
	}
	// Écoute passive en parallèle de la découverte.
	var passive chan []rawnet.Seen
	if adv != nil && opt.Passive > 0 {
		passive = make(chan []rawnet.Seen, 1)
		go func() { passive <- adv.listen(ctx, opt.Passive) }()
	}

	// 1. Découverte.
	var hosts []discovery.Host
	if opt.NoDiscovery {
		for _, a := range opt.Targets {
			hosts = append(hosts, discovery.Host{IP: a})
		}
	} else {
		var err error
		hosts, err = discovery.Run(ctx, opt.Targets, discovery.Options{Rate: opt.Rate, NoDNS: opt.NoDNS, Progress: progress(PhaseDiscovery)})
		if err != nil {
			return nil, err
		}
	}
	if adv != nil {
		hosts = adv.arpSweep(ctx, opt.Targets, opt.Rate, hosts)
	}
	if passive != nil {
		if opt.Progress != nil {
			opt.Progress(PhasePassive, 0, 1)
		}
		hosts = mergeSeen(hosts, <-passive, opt.Targets)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ips := make([]netip.Addr, len(hosts))
	index := make(map[netip.Addr]int, len(hosts))
	res.Hosts = make([]Host, len(hosts))
	for i, h := range hosts {
		ips[i] = h.IP
		index[h.IP] = i
		res.Hosts[i] = Host{Host: h}
	}

	// 2. Ports.
	ports := opt.Profile.Ports()
	if testPorts != nil {
		ports = testPorts
	}
	popt := portscan.Options{Ports: ports, Rate: opt.Rate, Progress: progress(PhasePorts)}
	if !opt.NoUDP {
		popt.UDP = portscan.DefaultUDPProbes
	}
	var open []portscan.Result
	if adv != nil {
		synOpen, connectIPs, synIPs := adv.synScan(ctx, hosts, ports, opt.Rate, progress(PhasePorts))
		open = append(open, synOpen...)
		// Hors sous-réseau local : scan « connect » ; UDP pour tous.
		r1, err := portscan.Scan(ctx, connectIPs, popt)
		if err != nil {
			return nil, err
		}
		udpOnly := popt
		udpOnly.Ports = []int{}
		r2, err := portscan.Scan(ctx, synIPs, udpOnly)
		if err != nil {
			return nil, err
		}
		open = append(append(open, r1...), r2...)
		portscan.SortResults(open)
	} else {
		var err error
		if open, err = portscan.Scan(ctx, ips, popt); err != nil {
			return nil, err
		}
	}

	// 3. Services TCP.
	var targets []probe.Target
	var where [][2]int
	for _, o := range open {
		hi := index[o.IP]
		p := Port{Port: o.Port, Proto: o.Proto, Response: o.Response}
		if o.Proto == "udp" {
			p.Service.Name = o.Service
		}
		res.Hosts[hi].Ports = append(res.Hosts[hi].Ports, p)
		if o.Proto == "tcp" {
			targets = append(targets, probe.Target{IP: o.IP, Port: o.Port})
			where = append(where, [2]int{hi, len(res.Hosts[hi].Ports) - 1})
		}
	}
	services := probe.All(ctx, targets, 32, 100, probe.Options{}, progress(PhaseProbes))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for i, s := range services {
		w := where[i]
		p := &res.Hosts[w[0]].Ports[w[1]]
		if s.Name == "" {
			s.Name = portscan.ServiceName(p.Port)
		}
		p.Service = s
	}
	// 4. Protocoles de découverte (NetBIOS, mDNS, SSDP/UPnP, SNMP, DNS).
	enrich(ctx, res.Hosts, progress(PhaseEnrich))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sigs := fingerprint.DefaultSignatures()
	for i := range res.Hosts {
		h := &res.Hosts[i]
		h.Type, h.Extra.Product = fingerprint.Guess(sigs, Evidence(*h))
	}
	res.Finished = time.Now()
	return res, nil
}
