package audit

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/maxb1906/arpent/internal/probe"
)

// Extra rassemble ce que les protocoles de découverte disent d'un appareil.
type Extra struct {
	NetBIOS      *probe.NetBIOSInfo `json:"netbios,omitempty"`
	MDNSName     string             `json:"mdns_name,omitempty"`
	MDNSServices []string           `json:"mdns_services,omitempty"`
	SSDP         *probe.SSDPInfo    `json:"ssdp,omitempty"`
	SNMPDescr    string             `json:"snmp_descr,omitempty"`
	DNSVersion   string             `json:"dns_version,omitempty"`
	Product      string             `json:"product,omitempty"` // produit deviné (signatures)
}

// enrich décode les réponses UDP et interroge mDNS (nom) et UPnP (description).
func enrich(ctx context.Context, hosts []Host, progress func(int, int)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	var mu sync.Mutex
	done := 0
	for i := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h *Host) {
			defer wg.Done()
			defer func() { <-sem }()
			enrichHost(ctx, h)
			if progress != nil {
				mu.Lock()
				done++
				progress(done, len(hosts))
				mu.Unlock()
			}
		}(&hosts[i])
	}
	wg.Wait()
}

func enrichHost(ctx context.Context, h *Host) {
	for i := range h.Ports {
		p := &h.Ports[i]
		if p.Proto != "udp" || len(p.Response) == 0 {
			continue
		}
		switch p.Port {
		case 137:
			if nb, err := probe.ParseNBSTAT(p.Response); err == nil {
				h.Extra.NetBIOS = nb
				p.Service.Banner = strings.Join(nb.Names, " ")
				if nb.Name != "" {
					h.Names = appendName(h.Names, nb.Name)
				}
			}
		case 161:
			if d, err := probe.ParseSNMPSysDescr(p.Response); err == nil {
				h.Extra.SNMPDescr = d
				p.Service.Banner = d
			}
		case 53:
			if v, err := probe.ParseDNSTXT(p.Response); err == nil {
				h.Extra.DNSVersion = v
				p.Service.Product, p.Service.Version = splitDash(v)
				p.Service.Banner = v
			}
		case 1900:
			if s, err := probe.ParseSSDP(p.Response); err == nil {
				if s.Location != "" {
					c, cancel := context.WithTimeout(ctx, 4*time.Second)
					probe.FetchUPnPDescription(c, h.IP, s, 4*time.Second)
					cancel()
				}
				h.Extra.SSDP = s
				p.Service.Banner = s.Server
			}
		case 5353:
			h.Extra.MDNSServices = probe.ParseMDNSPointers(p.Response)
			p.Service.Banner = strings.Join(h.Extra.MDNSServices, " ")
		}
	}
	// Nom .local : on ne le demande qu'aux appareils qui parlent mDNS.
	if hasUDP(h, 5353) {
		if n := probe.MDNSReverseName(ctx, h.IP, 1500*time.Millisecond); n != "" {
			h.Extra.MDNSName = n
			h.Names = appendName(h.Names, n)
		}
	}
}

func hasUDP(h *Host, port int) bool {
	for _, p := range h.Ports {
		if p.Proto == "udp" && p.Port == port {
			return true
		}
	}
	return false
}

// appendName ajoute un nom s'il n'est pas déjà présent (casse ignorée,
// « nom » et « nom.local » considérés égaux).
func appendName(names []string, n string) []string {
	base := strings.ToLower(strings.TrimSuffix(n, ".local"))
	for _, x := range names {
		if strings.ToLower(strings.TrimSuffix(strings.SplitN(x, ".", 2)[0], ".local")) == base || strings.EqualFold(x, n) {
			return names
		}
	}
	return append(names, n)
}

// splitDash sépare « dnsmasq-2.90 » en ("dnsmasq", "2.90").
func splitDash(s string) (string, string) {
	if i := strings.LastIndexAny(s, "-/ "); i > 0 && i < len(s)-1 && s[i+1] >= '0' && s[i+1] <= '9' {
		return s[:i], s[i+1:]
	}
	return s, ""
}
