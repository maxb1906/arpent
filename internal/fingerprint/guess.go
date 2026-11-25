package fingerprint

import (
	"fmt"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/maxb1906/arpent/assets"
)

// Types d'appareils reconnus (clés de traduction type.<type>).
var Types = []string{"router", "firewall", "switch", "access_point", "server", "hypervisor", "nas", "pc", "phone",
	"printer", "camera", "nvr", "tv", "media_player", "speaker", "game_console", "smart_home", "iot", "voip", "ups"}

// Evidence regroupe les indices observés sur un appareil.
type Evidence struct {
	Vendor      string
	RandomMAC   bool
	Names       []string
	Ports       []string // « 80/tcp »
	HTTPTitles  []string
	HTTPServers []string // Server, X-Powered-By
	Banners     []string
	Products    []string
	SSDP        string // type, fabricant, modèle, serveur concaténés
	MDNS        []string
	SNMP        string
	NetBIOS     bool
	ProductHint string // libellé par défaut (ex. fabricant + modèle UPnP)
}

// Signature est une règle de reconnaissance.
type Signature struct {
	Type       string   `yaml:"type"`
	Weight     int      `yaml:"weight"`
	Product    string   `yaml:"product"`
	Vendor     string   `yaml:"vendor"`
	Name       string   `yaml:"name"`
	HTTPTitle  string   `yaml:"http_title"`
	HTTPServer string   `yaml:"http_server"`
	SSDP       string   `yaml:"ssdp"`
	MDNS       string   `yaml:"mdns"`
	SNMP       string   `yaml:"snmp"`
	Banner     string   `yaml:"banner"`
	ProductRe  string   `yaml:"product_re"`
	Ports      []string `yaml:"ports"`
	AnyPorts   []string `yaml:"any_ports"`
	NetBIOS    bool     `yaml:"netbios"`
	RandomMAC  bool     `yaml:"random_mac"`

	re map[string]*regexp.Regexp
}

// LoadSignatures lit et compile un fichier de signatures.
func LoadSignatures(data []byte) ([]Signature, error) {
	var ss []Signature
	if err := yaml.Unmarshal(data, &ss); err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, t := range Types {
		known[t] = true
	}
	for i := range ss {
		s := &ss[i]
		if !known[s.Type] {
			return nil, fmt.Errorf("signature %d : type inconnu %q", i+1, s.Type)
		}
		if s.Weight <= 0 {
			s.Weight = 1
		}
		s.re = map[string]*regexp.Regexp{}
		for k, v := range map[string]string{"vendor": s.Vendor, "name": s.Name, "http_title": s.HTTPTitle, "http_server": s.HTTPServer,
			"ssdp": s.SSDP, "mdns": s.MDNS, "snmp": s.SNMP, "banner": s.Banner, "product": s.ProductRe} {
			if v == "" {
				continue
			}
			re, err := regexp.Compile("(?i)" + v)
			if err != nil {
				return nil, fmt.Errorf("signature %d (%s) : %w", i+1, k, err)
			}
			s.re[k] = re
		}
	}
	return ss, nil
}

var defaultSigs []Signature

// DefaultSignatures renvoie les signatures embarquées.
func DefaultSignatures() []Signature {
	if defaultSigs == nil {
		ss, err := LoadSignatures(assets.Signatures)
		if err != nil {
			panic("signatures.yaml embarqué invalide : " + err.Error())
		}
		defaultSigs = ss
	}
	return defaultSigs
}

func anyMatch(re *regexp.Regexp, vals ...string) bool {
	for _, v := range vals {
		if v != "" && re.MatchString(v) {
			return true
		}
	}
	return false
}

func (s *Signature) match(e Evidence) bool {
	ports := map[string]bool{}
	for _, p := range e.Ports {
		ports[p] = true
	}
	for _, p := range s.Ports {
		if !ports[p] {
			return false
		}
	}
	if len(s.AnyPorts) > 0 {
		ok := false
		for _, p := range s.AnyPorts {
			ok = ok || ports[p]
		}
		if !ok {
			return false
		}
	}
	if s.NetBIOS && !e.NetBIOS || s.RandomMAC && !e.RandomMAC {
		return false
	}
	checks := map[string][]string{
		"vendor": {e.Vendor}, "name": e.Names, "http_title": e.HTTPTitles, "http_server": e.HTTPServers,
		"ssdp": {e.SSDP}, "mdns": e.MDNS, "snmp": {e.SNMP}, "banner": e.Banners, "product": e.Products,
	}
	for k, re := range s.re {
		if !anyMatch(re, checks[k]...) {
			return false
		}
	}
	return true
}

// MinScore est le total minimal pour retenir un type.
const MinScore = 3

// Guess devine le type d'appareil et un libellé de produit à partir des indices.
func Guess(sigs []Signature, e Evidence) (string, string) {
	score := map[string]int{}
	product := map[string]string{}
	for i := range sigs {
		s := &sigs[i]
		if s.match(e) {
			score[s.Type] += s.Weight
			if s.Product != "" && product[s.Type] == "" {
				product[s.Type] = s.Product
			}
		}
	}
	best, bestScore := "", 0
	types := make([]string, 0, len(score))
	for t := range score {
		types = append(types, t)
	}
	sort.Strings(types) // départage stable
	for _, t := range types {
		if score[t] > bestScore {
			best, bestScore = t, score[t]
		}
	}
	if bestScore < MinScore {
		return "", ""
	}
	p := product[best]
	if p == "" {
		p = e.ProductHint
	}
	return best, p
}
