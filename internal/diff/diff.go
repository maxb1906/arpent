// Package diff compare deux audits d'un même site : appareils apparus ou
// disparus, ports ouverts ou fermés, services modifiés (version, certificat),
// changements d'adresse IP. L'identité d'un appareil est celle du stockage
// (MAC, à défaut IP + nom).
package diff

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/maxb1906/arpent/internal/netinfo"
	"github.com/maxb1906/arpent/internal/store"
)

// Compare renvoie les changements de prev vers cur. inScope dit si une
// adresse faisait partie des plages du nouvel audit : un appareil absent hors
// de ces plages n'est pas « disparu », il n'a simplement pas été cherché.
func Compare(prev, cur []store.Observation, inScope func(ip string) bool) []store.Change {
	if inScope == nil {
		inScope = func(string) bool { return true }
	}
	pd := byDevice(prev)
	cd := byDevice(cur)
	var out []store.Change

	for _, o := range cur {
		p, ok := pd[o.Device.ID]
		if !ok {
			out = append(out, store.Change{Kind: store.ChangeNewDevice, DeviceID: o.Device.ID, After: o.IP, IP: o.IP, Label: o.Device.Label, Known: o.Device.Known})
			continue
		}
		if p.IP != o.IP {
			out = append(out, store.Change{Kind: store.ChangeIPChanged, DeviceID: o.Device.ID, Before: p.IP, After: o.IP, IP: o.IP, Label: o.Device.Label, Known: o.Device.Known})
		}
		out = append(out, compareServices(p, o)...)
	}
	for _, p := range prev {
		if _, ok := cd[p.Device.ID]; !ok && inScope(p.IP) {
			out = append(out, store.Change{Kind: store.ChangeGoneDevice, DeviceID: p.Device.ID, Before: p.IP, IP: p.IP, Label: p.Device.Label, Known: p.Device.Known})
		}
	}
	// Même IP, autre appareil (MAC différente) : à signaler.
	prevByIP := map[string]store.Observation{}
	for _, p := range prev {
		prevByIP[p.IP] = p
	}
	for _, o := range cur {
		if p, ok := prevByIP[o.IP]; ok && p.Device.ID != o.Device.ID && p.MAC != "" && o.MAC != "" {
			out = append(out, store.Change{Kind: store.ChangeIPReassigned, DeviceID: o.Device.ID, Before: p.MAC, After: o.MAC, IP: o.IP, Label: o.Device.Label, Known: o.Device.Known})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return kindRank(out[i].Kind) < kindRank(out[j].Kind) })
	return out
}

func kindRank(k string) int {
	for i, x := range []string{store.ChangeNewDevice, store.ChangeIPReassigned, store.ChangePortOpened, store.ChangeServiceChanged,
		store.ChangeIPChanged, store.ChangePortClosed, store.ChangeGoneDevice} {
		if x == k {
			return i
		}
	}
	return 99
}

func byDevice(obs []store.Observation) map[int64]store.Observation {
	m := make(map[int64]store.Observation, len(obs))
	for _, o := range obs {
		m[o.Device.ID] = o
	}
	return m
}

func compareServices(p, o store.Observation) []store.Change {
	ps, cs := map[string]store.Service{}, map[string]store.Service{}
	for _, s := range p.Services {
		ps[s.Key()] = s
	}
	for _, s := range o.Services {
		cs[s.Key()] = s
	}
	base := store.Change{DeviceID: o.Device.ID, IP: o.IP, Label: o.Device.Label, Known: o.Device.Known}
	var out []store.Change
	for _, s := range o.Services {
		old, ok := ps[s.Key()]
		c := base
		c.Port, c.Proto = s.Port, s.Proto
		if !ok {
			c.Kind, c.After = store.ChangePortOpened, s.Name
			out = append(out, c)
			continue
		}
		for _, f := range fields {
			b, a := f.get(old), f.get(s)
			if b != a && (b != "" || a != "") {
				c.Kind, c.Field, c.Before, c.After = store.ChangeServiceChanged, f.name, b, a
				out = append(out, c)
			}
		}
	}
	for _, s := range p.Services {
		if _, ok := cs[s.Key()]; !ok {
			c := base
			c.Kind, c.Port, c.Proto, c.Before = store.ChangePortClosed, s.Port, s.Proto, s.Name
			out = append(out, c)
		}
	}
	return out
}

// fields : ce qui compte comme « service modifié ». Le titre d'une page web
// change trop souvent pour être pertinent ; on s'en tient aux identités.
var fields = []struct {
	name string
	get  func(store.Service) string
}{
	{"name", func(s store.Service) string { return s.Name }},
	{"product", func(s store.Service) string { return strings.TrimSpace(s.Product + " " + s.Version) }},
	{"server", func(s store.Service) string {
		if s.Details.HTTP == nil {
			return ""
		}
		return s.Details.HTTP.Server
	}},
	{"cert", func(s store.Service) string {
		t := s.Details.TLS
		if t == nil {
			return ""
		}
		return t.Subject + " · " + t.NotAfter.Format("2006-01-02") + " · " + t.SHA256[:min(12, len(t.SHA256))]
	}},
	{"ssh", func(s store.Service) string {
		if s.Details.SSH == nil {
			return ""
		}
		return strings.TrimSpace(s.Details.SSH.Software + " " + s.Details.SSH.Comment)
	}},
}

// ScopeFromRanges construit le test « adresse dans les plages » d'un audit.
func ScopeFromRanges(ranges string) func(string) bool {
	addrs, err := netinfo.ParseRanges(ranges)
	if err != nil || len(addrs) == 0 {
		return nil // inconnu : tout est dans le périmètre
	}
	set := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		set[a] = true
	}
	return func(ip string) bool {
		a, err := netip.ParseAddr(ip)
		return err == nil && set[a]
	}
}

// Between calcule les changements entre deux audits quelconques du site.
func Between(s *store.Site, prevID, curID int64) ([]store.Change, error) {
	prev, err := s.Observations(prevID)
	if err != nil {
		return nil, err
	}
	cur, err := s.Observations(curID)
	if err != nil {
		return nil, err
	}
	a, err := s.GetAudit(curID)
	if err != nil {
		return nil, err
	}
	cs := Compare(prev, cur, ScopeFromRanges(a.Ranges))
	for i := range cs {
		cs[i].AuditID, cs[i].PrevAudit = curID, prevID
	}
	return cs, nil
}

// Apply compare un audit enregistré au précédent et sauvegarde les
// changements (post-traitement de internal/engine).
func Apply(s *store.Site, auditID int64) error {
	prev, err := s.PreviousAudit(auditID)
	if err != nil || prev == 0 {
		return err
	}
	cs, err := Between(s, prev, auditID)
	if err != nil {
		return err
	}
	return s.SaveChanges(auditID, prev, cs)
}

// Summary compte les changements par type.
func Summary(cs []store.Change) map[string]int {
	m := map[string]int{}
	for _, c := range cs {
		m[c.Kind]++
	}
	return m
}

// Key renvoie une clé lisible « port/proto ».
func Key(c store.Change) string {
	if c.Port == 0 {
		return ""
	}
	return strconv.Itoa(c.Port) + "/" + c.Proto
}
