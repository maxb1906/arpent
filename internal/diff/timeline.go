package diff

import (
	"sort"
	"time"

	"github.com/maxb1906/arpent/internal/store"
)

// Événements propres à la frise d'un appareil.
const (
	EventFirstSeen  = "first_seen"
	EventReappeared = "reappeared"
)

// Event est un moment de la vie d'un appareil.
type Event struct {
	AuditID int64
	Date    time.Time
	Change  store.Change // Kind : un type de changement ou EventFirstSeen / EventReappeared
}

// Timeline reconstitue l'histoire d'un appareil sur tous les audits terminés
// du site : première apparition, changements d'IP, ports ouverts ou fermés,
// versions, disparition et retour.
func Timeline(s *store.Site, deviceID int64) ([]Event, error) {
	audits, err := s.Audits()
	if err != nil {
		return nil, err
	}
	var done []store.Audit
	for _, a := range audits {
		if a.Status == store.StatusDone {
			done = append(done, a)
		}
	}
	sort.Slice(done, func(i, j int) bool { return done[i].ID < done[j].ID })
	hist, err := s.DeviceHistory(deviceID)
	if err != nil {
		return nil, err
	}
	byAudit := map[int64]store.Observation{}
	for _, o := range hist {
		byAudit[o.AuditID] = o
	}
	return timeline(done, byAudit), nil
}

func timeline(audits []store.Audit, byAudit map[int64]store.Observation) []Event {
	var out []Event
	var last *store.Observation // dernière observation connue
	present := false
	for _, a := range audits {
		o, ok := byAudit[a.ID]
		switch {
		case ok && last == nil:
			out = append(out, Event{a.ID, a.Started, store.Change{Kind: EventFirstSeen, After: o.IP, IP: o.IP}})
		case ok && !present:
			out = append(out, Event{a.ID, a.Started, store.Change{Kind: EventReappeared, After: o.IP, IP: o.IP}})
			fallthrough
		case ok:
			for _, c := range Compare([]store.Observation{*last}, []store.Observation{o}, nil) {
				out = append(out, Event{a.ID, a.Started, c})
			}
		case !ok && present:
			if scope := ScopeFromRanges(a.Ranges); scope == nil || scope(last.IP) {
				out = append(out, Event{a.ID, a.Started, store.Change{Kind: store.ChangeGoneDevice, Before: last.IP, IP: last.IP}})
				present = false
			}
			continue
		default:
			continue
		}
		cp := o
		last, present = &cp, true
	}
	return out
}
