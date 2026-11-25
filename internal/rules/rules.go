// Package rules évalue les points d'attention d'un audit à partir des règles
// embarquées (assets/rules.yaml). Une règle produit un « finding » : un
// identifiant de règle, un niveau et des paramètres ; le texte est traduit à
// l'affichage, dans la langue de l'interface ou du rapport.
package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/maxb1906/arpent/assets"
	"github.com/maxb1906/arpent/internal/store"
)

// Niveaux, du plus grave au moins grave.
const (
	Critical = "critical"
	Warning  = "warning"
	Info     = "info"
)

// LevelRank ordonne les niveaux (0 = le plus grave).
func LevelRank(l string) int {
	switch l {
	case Critical:
		return 0
	case Warning:
		return 1
	}
	return 2
}

// Rule est une règle d'audit.
type Rule struct {
	ID    string `yaml:"id"`
	Level string `yaml:"level"`
	Match Match  `yaml:"match"`
}

// Match regroupe les conditions d'une règle.
type Match struct {
	Proto          string     `yaml:"proto"`
	Ports          []int      `yaml:"ports"`
	Services       []string   `yaml:"services"`
	HTTPPlainAdmin bool       `yaml:"http_plain_admin"`
	TLSExpired     bool       `yaml:"tls_expired"`
	TLSExpiresDays int        `yaml:"tls_expires_within_days"`
	TLSSelfSigned  bool       `yaml:"tls_self_signed"`
	TLSOldVersion  bool       `yaml:"tls_old_version"`
	SMBv1          bool       `yaml:"smb_v1"`
	SNMPPublic     bool       `yaml:"snmp_public"`
	SSDP           bool       `yaml:"ssdp"`
	SSHProtocolV1  bool       `yaml:"ssh_protocol_v1"`
	Outdated       []Outdated `yaml:"outdated"`
}

// Outdated : un produit est signalé si sa version est inférieure à Below.
type Outdated struct {
	Product string `yaml:"product"`
	Below   string `yaml:"below"`
}

// Load lit et valide un fichier de règles.
func Load(data []byte) ([]Rule, error) {
	var rs []Rule
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	for i, r := range rs {
		if r.ID == "" {
			return nil, fmt.Errorf("règle %d sans identifiant", i+1)
		}
		if r.Level != Critical && r.Level != Warning && r.Level != Info {
			return nil, fmt.Errorf("règle %s : niveau %q invalide", r.ID, r.Level)
		}
	}
	return rs, nil
}

// Default renvoie les règles embarquées.
func Default() []Rule {
	rs, err := Load(assets.Rules)
	if err != nil {
		panic("rules.yaml embarqué invalide : " + err.Error())
	}
	return rs
}

// Evaluate applique les règles à un audit. now sert aux dates d'expiration.
// Une même règle ne produit qu'un point par service.
func Evaluate(rs []Rule, obs []store.Observation, now time.Time) []store.Finding {
	var out []store.Finding
	for _, o := range obs {
		for _, sv := range o.Services {
			seen := map[string]bool{}
			for _, r := range rs {
				if seen[r.ID] {
					continue
				}
				if params, ok := r.Match.eval(sv, now); ok {
					seen[r.ID] = true
					params["port"] = strconv.Itoa(sv.Port)
					params["proto"] = sv.Proto
					params["service"] = sv.Name
					params["ip"] = o.IP
					out = append(out, store.Finding{DeviceID: o.Device.ID, ServiceID: sv.ID, Rule: r.ID, Level: r.Level, Params: params, IP: o.IP, Port: sv.Port, Proto: sv.Proto})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return LevelRank(out[i].Level) < LevelRank(out[j].Level) })
	return out
}

// adminWords : indices d'une page d'administration ou de connexion.
var adminWords = regexp.MustCompile(`(?i)\b(log ?in|sign ?in|password|passwd|admin|administration|connexion|mot de passe|identifiant|router|routeur|configuration|setup|webui|management|dashboard)\b`)

func (m Match) eval(sv store.Service, now time.Time) (map[string]string, bool) {
	p := map[string]string{}
	d := sv.Details
	if m.Proto != "" && m.Proto != sv.Proto {
		return nil, false
	}
	if len(m.Ports) > 0 && !containsInt(m.Ports, sv.Port) {
		return nil, false
	}
	if len(m.Services) > 0 && !containsStr(m.Services, sv.Name) {
		return nil, false
	}
	if m.HTTPPlainAdmin {
		h := d.HTTP
		if h == nil || d.TLS != nil || sv.Name != "http" {
			return nil, false
		}
		if h.AuthRealm == "" && !adminWords.MatchString(h.Title) && !adminWords.MatchString(h.BodySample) {
			return nil, false
		}
		if h.Title != "" {
			p["title"] = h.Title
		} else {
			p["title"] = h.AuthRealm
		}
	}
	if m.TLSExpired || m.TLSExpiresDays > 0 || m.TLSSelfSigned || m.TLSOldVersion {
		t := d.TLS
		if t == nil {
			return nil, false
		}
		p["subject"] = t.Subject
		p["date"] = t.NotAfter.Format("2006-01-02")
		if m.TLSExpired && !now.After(t.NotAfter) {
			return nil, false
		}
		if m.TLSExpiresDays > 0 {
			left := t.NotAfter.Sub(now)
			if left < 0 || left > time.Duration(m.TLSExpiresDays)*24*time.Hour {
				return nil, false
			}
			p["days"] = strconv.Itoa(int(left.Hours() / 24))
		}
		if m.TLSSelfSigned && !t.SelfSigned {
			return nil, false
		}
		if m.TLSOldVersion {
			if t.Version != "TLS 1.0" && t.Version != "TLS 1.1" && !strings.HasPrefix(t.Version, "SSL") {
				return nil, false
			}
			p["version"] = t.Version
		}
	}
	if m.SMBv1 && (d.SMB == nil || !d.SMB.SMBv1) {
		return nil, false
	}
	if m.SNMPPublic && !(sv.Proto == "udp" && sv.Port == 161 && len(sv.Raw) > 2 && sv.Raw[0] == 0x30) {
		return nil, false
	}
	if m.SSDP && !(sv.Proto == "udp" && sv.Port == 1900 && len(sv.Raw) > 0) {
		return nil, false
	}
	if m.SSHProtocolV1 {
		if d.SSH == nil || !strings.HasPrefix(d.SSH.Protocol, "1") {
			return nil, false
		}
		p["version"] = d.SSH.Protocol
	}
	if len(m.Outdated) > 0 {
		hit := false
		for _, cand := range products(sv) {
			for _, o := range m.Outdated {
				if strings.EqualFold(cand[0], o.Product) && cand[1] != "" && VersionLess(cand[1], o.Below) {
					p["product"], p["version"] = cand[0], cand[1]
					hit = true
				}
			}
		}
		if !hit {
			return nil, false
		}
	}
	return p, true
}

// products renvoie les couples (produit, version) annoncés par un service :
// produit identifié, en-têtes Server et X-Powered-By.
func products(sv store.Service) [][2]string {
	out := [][2]string{{sv.Product, sv.Version}}
	if h := sv.Details.HTTP; h != nil {
		for _, hdr := range []string{h.Server, h.PoweredBy} {
			for _, tok := range strings.Fields(hdr) {
				if name, ver, ok := strings.Cut(tok, "/"); ok {
					out = append(out, [2]string{name, ver})
				}
			}
		}
	}
	return out
}

var numRe = regexp.MustCompile(`\d+`)

// VersionLess compare deux versions par leurs nombres successifs :
// « 7.4p1 » < « 8.0 », « 2.4.41 » < « 2.4.58 ».
func VersionLess(a, b string) bool {
	x, y := numRe.FindAllString(a, -1), numRe.FindAllString(b, -1)
	if len(x) == 0 {
		return false
	}
	for i := 0; i < len(x) || i < len(y); i++ {
		var xi, yi int
		if i < len(x) {
			xi, _ = strconv.Atoi(x[i])
		}
		if i < len(y) {
			yi, _ = strconv.Atoi(y[i])
		}
		if xi != yi {
			return xi < yi
		}
	}
	return false
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// Apply évalue les règles embarquées sur un audit enregistré et sauvegarde
// les points d'attention (post-traitement de internal/engine).
func Apply(s *store.Site, auditID int64) error {
	obs, err := s.Observations(auditID)
	if err != nil {
		return err
	}
	return s.SaveFindings(auditID, Evaluate(Default(), obs, time.Now()))
}
