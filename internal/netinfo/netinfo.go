// Package netinfo donne les interfaces réseau, les sous-réseaux à proposer
// pour un audit et la table ARP (voisins IPv4 → MAC) propre à chaque OS.
//
// Rien ici n'exige de droits administrateur.
package netinfo

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// ErrNotSupported est renvoyée quand une fonction n'existe pas sur l'OS courant.
var ErrNotSupported = errors.New("netinfo: non pris en charge sur ce système")

// Interface décrit une interface réseau de la machine.
type Interface struct {
	Index    int
	Name     string
	MAC      net.HardwareAddr
	Up       bool
	Loopback bool
	Prefixes []netip.Prefix // adresses IPv4 avec leur masque (ex. 192.168.1.20/24)
}

// Interfaces liste les interfaces de la machine avec leurs adresses IPv4.
func Interfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(ifs))
	for _, i := range ifs {
		it := Interface{
			Index:    i.Index,
			Name:     i.Name,
			MAC:      i.HardwareAddr,
			Up:       i.Flags&net.FlagUp != 0,
			Loopback: i.Flags&net.FlagLoopback != 0,
		}
		addrs, err := i.Addrs()
		if err == nil {
			for _, a := range addrs {
				if p, ok := prefixFromAddr(a); ok {
					it.Prefixes = append(it.Prefixes, p)
				}
			}
		}
		out = append(out, it)
	}
	return out, nil
}

func prefixFromAddr(a net.Addr) (netip.Prefix, bool) {
	ipn, ok := a.(*net.IPNet)
	if !ok {
		return netip.Prefix{}, false
	}
	ip4 := ipn.IP.To4()
	if ip4 == nil {
		return netip.Prefix{}, false
	}
	ones, bits := ipn.Mask.Size()
	if bits == 128 { // masque IPv6 sur une adresse IPv4 mappée
		ones -= 96
	}
	if ones < 0 || ones > 32 {
		return netip.Prefix{}, false
	}
	addr, _ := netip.AddrFromSlice(ip4)
	return netip.PrefixFrom(addr, ones), true
}

// MaxSuggestedBits est la taille minimale d'un sous-réseau proposé : au-delà
// d'un /22 (1022 hôtes), on propose le /24 qui contient l'adresse de la machine.
const MaxSuggestedBits = 22

// Subnet est un sous-réseau proposé pour l'audit.
type Subnet struct {
	Interface string
	Address   netip.Addr   // adresse de la machine sur ce réseau
	Prefix    netip.Prefix // réseau à scanner (masqué)
	Reduced   bool         // vrai si le réseau réel était plus grand et a été réduit
}

// SuggestSubnets propose les sous-réseaux IPv4 à auditer : interfaces actives,
// hors boucle locale et hors adresses lien-local (169.254.0.0/16). Les
// doublons sont supprimés.
func SuggestSubnets(ifs []Interface) []Subnet {
	seen := map[netip.Prefix]bool{}
	var out []Subnet
	for _, i := range ifs {
		if !i.Up || i.Loopback || isVirtualName(i.Name) {
			continue
		}
		for _, p := range i.Prefixes {
			a := p.Addr()
			if a.IsLoopback() || a.IsLinkLocalUnicast() || p.Bits() >= 31 {
				continue
			}
			s := Subnet{Interface: i.Name, Address: a, Prefix: p.Masked()}
			if p.Bits() < MaxSuggestedBits {
				s.Prefix = netip.PrefixFrom(a, 24).Masked()
				s.Reduced = true
			}
			if seen[s.Prefix] {
				continue
			}
			seen[s.Prefix] = true
			out = append(out, s)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Prefix.Addr().Less(out[b].Prefix.Addr()) })
	return out
}

// isVirtualName écarte les interfaces virtuelles courantes (Docker, VPN de
// conteneurs…) qui ne correspondent pas au réseau audité.
func isVirtualName(name string) bool {
	n := strings.ToLower(name)
	for _, p := range []string{"docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "lxc", "cni", "flannel"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// Hosts renvoie les adresses d'hôte d'un préfixe IPv4 (sans l'adresse de
// réseau ni de diffusion pour les préfixes plus courts qu'un /31).
func Hosts(p netip.Prefix) []netip.Addr {
	p = p.Masked()
	if !p.Addr().Is4() {
		return nil
	}
	n := 1 << (32 - p.Bits())
	out := make([]netip.Addr, 0, n)
	a := p.Addr()
	for i := 0; i < n; i++ {
		out = append(out, a)
		a = a.Next()
	}
	if p.Bits() < 31 && len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out
}

// ParseRanges lit une liste de plages séparées par des virgules ou des
// espaces : CIDR (192.168.1.0/24), adresse seule, ou intervalle
// (192.168.1.10-192.168.1.50 ou 192.168.1.10-50).
func ParseRanges(s string) ([]netip.Addr, error) {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(a netip.Addr) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	if len(fields) == 0 {
		return nil, errors.New("plage vide")
	}
	for _, f := range fields {
		switch {
		case strings.Contains(f, "/"):
			p, err := netip.ParsePrefix(f)
			if err != nil || !p.Addr().Is4() {
				return nil, errors.New("plage invalide : " + f)
			}
			if p.Bits() < 16 {
				return nil, errors.New("plage trop grande (au plus un /16) : " + f)
			}
			for _, a := range Hosts(p) {
				add(a)
			}
		case strings.Contains(f, "-"):
			lo, hi, _ := strings.Cut(f, "-")
			start, err := netip.ParseAddr(lo)
			if err != nil || !start.Is4() {
				return nil, errors.New("plage invalide : " + f)
			}
			if !strings.Contains(hi, ".") { // forme courte : 192.168.1.10-50
				b := start.As4()
				hi = fmt.Sprintf("%d.%d.%d.%s", b[0], b[1], b[2], hi)
			}
			end, err := netip.ParseAddr(hi)
			if err != nil || !end.Is4() || end.Less(start) {
				return nil, errors.New("plage invalide : " + f)
			}
			count := 0
			for a := start; ; a = a.Next() {
				add(a)
				count++
				if a == end {
					break
				}
				if count > 65536 {
					return nil, errors.New("plage trop grande : " + f)
				}
			}
		default:
			a, err := netip.ParseAddr(f)
			if err != nil || !a.Is4() {
				return nil, errors.New("adresse invalide : " + f)
			}
			add(a)
		}
	}
	return out, nil
}
