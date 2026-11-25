// Package rawnet est le « mode avancé » d'Arpent (§ 11.3) : envoi et
// réception de trames Ethernet brutes pour l'ARP brut, le scan SYN et
// l'écoute passive. Il exige Npcap + administrateur sous Windows, root (ou
// CAP_NET_RAW) sous Linux ; ailleurs ou sinon, Available renvoie false et
// Arpent reste en mode standard, sans message d'erreur.
package rawnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// ErrNotSupported : mode avancé indisponible sur ce système.
var ErrNotSupported = errors.New("rawnet: mode avancé non pris en charge")

// ErrTimeout est renvoyée par ReadPacket quand aucun paquet n'arrive à temps.
var ErrTimeout = errors.New("rawnet: délai dépassé")

// Handle envoie et reçoit des trames Ethernet sur une interface.
type Handle interface {
	WritePacket(frame []byte) error
	// ReadPacket renvoie la prochaine trame, ou ErrTimeout après d (environ).
	ReadPacket(d time.Duration) ([]byte, error)
	Close() error
}

// Iface décrit l'interface utilisée en mode avancé.
type Iface struct {
	Name   string
	Index  int
	MAC    net.HardwareAddr
	IP     netip.Addr
	Prefix netip.Prefix
}

// Status décrit la disponibilité du mode avancé.
type Status struct {
	Available bool
	Driver    string // « npcap », « af_packet »
	Reason    string // clé de traduction si indisponible (advanced.reason.*)
}

// Check indique si le mode avancé est utilisable.
func Check() Status { return check() }

// Open ouvre l'interface en mode avancé.
func Open(ifc Iface) (Handle, error) { return open(ifc) }

// ForPrefix choisit l'interface qui porte le sous-réseau p.
func ForPrefix(p netip.Prefix) (Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return Iface{}, err
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || len(i.HardwareAddr) != 6 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			ip, _ := netip.AddrFromSlice(ipn.IP.To4())
			ones, _ := ipn.Mask.Size()
			pref := netip.PrefixFrom(ip, ones).Masked()
			if pref.Overlaps(p) {
				return Iface{Name: i.Name, Index: i.Index, MAC: i.HardwareAddr, IP: ip, Prefix: pref}, nil
			}
		}
	}
	return Iface{}, errors.New("rawnet: aucune interface sur " + p.String())
}

// readLoop lit des trames jusqu'à ctx ou deadline, et les passe à fn.
func readLoop(ctx context.Context, h Handle, until time.Time, fn func([]byte)) {
	for ctx.Err() == nil && time.Now().Before(until) {
		f, err := h.ReadPacket(200 * time.Millisecond)
		if errors.Is(err, ErrTimeout) {
			continue
		}
		if err != nil {
			return
		}
		fn(f)
	}
}
