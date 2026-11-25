// Package report produit le rapport d'audit remis au client : un fichier
// HTML autonome (CSS intégré, lisible hors ligne, imprimable en PDF), et les
// exports CSV/JSON de l'inventaire. La langue du rapport est choisie
// indépendamment de celle de l'interface.
package report

import (
	"fmt"
	"html/template"
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
	// Émetteur (profil du technicien) ; vide par défaut.
	Issuer Issuer
	// Comment est la synthèse libre du technicien ; Recos remplace, par
	// règle, la recommandation par défaut.
	Comment string
	Recos   map[string]string
	// Kind est le type de rapport (Kinds).
	Kind string
}

// Types de rapport (§ 11.2).
const (
	KindFull      = "full"      // complet
	KindExecutive = "executive" // résumé direction, non technique
	KindTechnical = "technical" // tout le détail technique
	KindChanges   = "changes"   // évolution seulement
)

// Kinds liste les types de rapport.
var Kinds = []string{KindFull, KindExecutive, KindTechnical, KindChanges}

// Has indique si une section figure dans ce type de rapport.
func (d *Data) Has(section string) bool {
	k := d.Kind
	switch section {
	case "summary":
		return k != KindTechnical
	case "findings":
		return k == KindFull || k == KindTechnical
	case "changes":
		return d.Previous != nil && (k == KindFull || k == KindChanges || k == KindExecutive)
	case "inventory":
		return k == KindFull || k == KindTechnical
	case "annex":
		return k == KindFull || k == KindTechnical
	case "method":
		return true
	}
	return false
}

// Fix renvoie la recommandation personnalisée d'une règle, ou "".
func (d *Data) Fix(rule string) string { return d.Recos[rule] }

// Issuer décrit l'émetteur du rapport.
type Issuer struct {
	Name, Company, Contact, Legal, Color string
	LogoDataURI                          template.URL // image en data: URI (contenu sûr : lu localement)
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
	d := &Data{Site: info, Audit: a, Generated: time.Now(), Generator: generator, Types: map[string]int{}, Kind: KindFull}
	if d.Comment, err = s.Comment(auditID); err != nil {
		return nil, err
	}
	if d.Recos, err = s.Recommendations(auditID); err != nil {
		return nil, err
	}
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

// FileName renvoie le nom de fichier d'un rapport : 2026-11-25_audit-3.html
// (complet) ou 2026-11-25_audit-3_executive.pdf (autre type).
func FileName(a store.Audit, ext string) string { return KindFileName(a, KindFull, ext) }

// KindFileName : comme FileName, pour un type de rapport donné.
func KindFileName(a store.Audit, kind, ext string) string {
	n := a.Started.Local().Format("2006-01-02") + "_audit-" + strconv.FormatInt(a.ID, 10)
	if kind != "" && kind != KindFull {
		n += "_" + kind
	}
	return n + "." + ext
}

// Path renvoie le chemin d'un rapport dans le dossier du site.
func Path(s *store.Site, a store.Audit, ext string) string {
	return filepath.Join(s.ReportsDir(), FileName(a, ext))
}

// KindPath : comme Path, pour un type de rapport donné.
func KindPath(s *store.Site, a store.Audit, kind, ext string) string {
	return filepath.Join(s.ReportsDir(), KindFileName(a, kind, ext))
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
