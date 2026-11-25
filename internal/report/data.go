// Package report produit le rapport d'audit remis au client : un fichier
// HTML autonome (CSS intégré, lisible hors ligne, imprimable en PDF), et les
// exports CSV/JSON de l'inventaire. La langue du rapport est choisie
// indépendamment de celle de l'interface.
package report

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/maxb1906/arpent/internal/store"
)

// Data rassemble tout ce qu'affiche un rapport.
type Data struct {
	Site         store.SiteInfo
	Audit        store.Audit
	Previous     *store.Audit
	Observations []store.Observation
	Findings     []store.Finding
	Changes      []store.Change
	Counts       map[string]int // points d'attention par niveau
	ChangeCounts map[string]int
	Types        map[string]int // appareils par type
	OpenPorts    int
	Unknown      int // nouveaux appareils non validés
	Generated    time.Time
	Generator    string // « Arpent v… »
	// Émetteur (profil du technicien, étape 13) ; vide par défaut.
	Issuer Issuer
}

// Issuer décrit l'émetteur du rapport.
type Issuer struct {
	Name, Company, Contact, Legal, Color string
	LogoDataURI                          string // image en data: URI
}

// Build charge les données d'un audit terminé.
func Build(s *store.Site, auditID int64, generator string) (*Data, error) {
	a, err := s.GetAudit(auditID)
	if err != nil {
		return nil, err
	}
	if a.Status != store.StatusDone {
		return nil, fmt.Errorf("audit %d non terminé (%s)", auditID, a.Status)
	}
	info, err := s.Info()
	if err != nil {
		return nil, err
	}
	d := &Data{Site: info, Audit: a, Generated: time.Now(), Generator: generator, Types: map[string]int{}}
	if d.Observations, err = s.Observations(auditID); err != nil {
		return nil, err
	}
	if d.Findings, err = s.Findings(auditID); err != nil {
		return nil, err
	}
	if d.Changes, err = s.Changes(auditID); err != nil {
		return nil, err
	}
	if prev, _ := s.PreviousAudit(auditID); prev != 0 {
		if pa, err := s.GetAudit(prev); err == nil {
			d.Previous = &pa
		}
	}
	d.Counts = store.FindingCounts(d.Findings)
	d.ChangeCounts = map[string]int{}
	for _, c := range d.Changes {
		d.ChangeCounts[c.Kind]++
		if c.Kind == store.ChangeNewDevice && !c.Known {
			d.Unknown++
		}
	}
	for _, o := range d.Observations {
		t := o.DeviceType
		if t == "" {
			t = "unknown"
		}
		d.Types[t]++
		d.OpenPorts += len(o.Services)
	}
	return d, nil
}

// Risk résume le niveau de risque global : high, medium ou low.
func (d *Data) Risk() string {
	switch {
	case d.Counts["critical"] > 0:
		return "high"
	case d.Counts["warning"] > 0:
		return "medium"
	}
	return "low"
}

// FindingsOf renvoie les points d'attention d'un appareil.
func (d *Data) FindingsOf(deviceID int64) []store.Finding {
	var out []store.Finding
	for _, f := range d.Findings {
		if f.DeviceID == deviceID {
			out = append(out, f)
		}
	}
	return out
}

// FileName renvoie le nom de fichier d'un rapport : 2026-11-25_audit-3.html.
func FileName(a store.Audit, ext string) string {
	return a.Started.Local().Format("2006-01-02") + "_audit-" + strconv.FormatInt(a.ID, 10) + "." + ext
}

// Path renvoie le chemin d'un rapport dans le dossier du site.
func Path(s *store.Site, a store.Audit, ext string) string {
	return filepath.Join(s.ReportsDir(), FileName(a, ext))
}

// Group rassemble les points d'attention d'une même règle.
type Group struct {
	Rule   string
	Level  string
	First  store.Finding
	Items  []store.Finding
	Device int // appareils concernés
}

// Groups regroupe les points d'attention par règle, du plus grave au moins grave.
func (d *Data) Groups() []Group {
	var out []Group
	idx := map[string]int{}
	for _, f := range d.Findings {
		i, ok := idx[f.Rule]
		if !ok {
			i = len(out)
			idx[f.Rule] = i
			out = append(out, Group{Rule: f.Rule, Level: f.Level, First: f})
		}
		out[i].Items = append(out[i].Items, f)
	}
	for i := range out {
		seen := map[int64]bool{}
		for _, f := range out[i].Items {
			seen[f.DeviceID] = true
		}
		out[i].Device = len(seen)
	}
	return out
}
