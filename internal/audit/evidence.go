package audit

import (
	"strconv"
	"strings"

	"github.com/maxb1906/arpent/internal/fingerprint"
)

// Evidence rassemble les indices d'un appareil pour la devinette du type.
func Evidence(h Host) fingerprint.Evidence {
	e := fingerprint.Evidence{Vendor: h.Vendor, RandomMAC: h.Random, Names: h.Names, MDNS: h.Extra.MDNSServices,
		SNMP: h.Extra.SNMPDescr, NetBIOS: h.Extra.NetBIOS != nil}
	if h.Extra.NetBIOS != nil {
		e.Names = append(append([]string{}, e.Names...), h.Extra.NetBIOS.Name)
	}
	if h.Extra.MDNSName != "" {
		e.Names = append(e.Names, h.Extra.MDNSName)
	}
	if s := h.Extra.SSDP; s != nil {
		e.SSDP = strings.Join([]string{s.FriendlyName, s.Manufacturer, s.ModelName, s.ModelNumber, s.DeviceType, s.Server}, " | ")
		e.ProductHint = strings.TrimSpace(s.Manufacturer + " " + s.ModelName)
	}
	for _, p := range h.Ports {
		e.Ports = append(e.Ports, strconv.Itoa(p.Port)+"/"+p.Proto)
		sv := p.Service
		if sv.Product != "" {
			e.Products = append(e.Products, sv.Product)
		}
		if sv.Banner != "" {
			e.Banners = append(e.Banners, sv.Banner)
		}
		if h := sv.HTTP; h != nil {
			if h.Title != "" {
				e.HTTPTitles = append(e.HTTPTitles, h.Title)
			}
			if h.AuthRealm != "" {
				e.HTTPTitles = append(e.HTTPTitles, h.AuthRealm)
			}
			for _, v := range []string{h.Server, h.PoweredBy} {
				if v != "" {
					e.HTTPServers = append(e.HTTPServers, v)
				}
			}
		}
		if t := sv.TLS; t != nil && t.Subject != "" {
			e.Names = append(e.Names, t.Subject)
		}
	}
	return e
}
