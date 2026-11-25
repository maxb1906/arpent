package netinfo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
)

// Neighbor est une entrée de la table ARP : une adresse IPv4 et sa MAC.
type Neighbor struct {
	IP        netip.Addr
	MAC       net.HardwareAddr
	Interface string // nom ou index de l'interface, selon l'OS
}

// ARPTable lit la table ARP (voisins IPv4) de l'OS. Les entrées incomplètes
// ou sans MAC sont ignorées.
func ARPTable() ([]Neighbor, error) { return arpTable() }

// ActiveARP envoie une requête ARP à ip et renvoie sa MAC, sans droits
// administrateur. Disponible uniquement sous Windows (API SendARP) ;
// ailleurs, renvoie ErrNotSupported.
func ActiveARP(ctx context.Context, ip netip.Addr) (net.HardwareAddr, error) {
	return activeARP(ctx, ip)
}

// ActiveARPSupported indique si ActiveARP est disponible sur cet OS.
func ActiveARPSupported() bool { return activeARPSupported }

func validMAC(m net.HardwareAddr) bool {
	if len(m) != 6 {
		return false
	}
	zero, bcast := true, true
	for _, b := range m {
		if b != 0 {
			zero = false
		}
		if b != 0xff {
			bcast = false
		}
	}
	return !zero && !bcast
}

// parseProcNetARP lit le format de /proc/net/arp (Linux).
func parseProcNetARP(r io.Reader) ([]Neighbor, error) {
	var out []Neighbor
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil || !ip.Is4() {
			continue
		}
		// Flags : 0x2 = ATF_COM (entrée complète).
		if f[2] == "0x0" {
			continue
		}
		mac, err := net.ParseMAC(f[3])
		if err != nil || !validMAC(mac) {
			continue
		}
		out = append(out, Neighbor{IP: ip, MAC: mac, Interface: f[5]})
	}
	return out, sc.Err()
}

// parseArpAn lit la sortie de « arp -an » (macOS / BSD) :
//
//	? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
func parseArpAn(r io.Reader) ([]Neighbor, error) {
	var out []Neighbor
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[2] != "at" {
			continue
		}
		ip, err := netip.ParseAddr(strings.Trim(f[1], "()"))
		if err != nil || !ip.Is4() {
			continue
		}
		mac, err := parseLooseMAC(f[3])
		if err != nil || !validMAC(mac) {
			continue
		}
		n := Neighbor{IP: ip, MAC: mac}
		for i := 4; i+1 < len(f); i++ {
			if f[i] == "on" {
				n.Interface = f[i+1]
				break
			}
		}
		out = append(out, n)
	}
	return out, sc.Err()
}

// parseLooseMAC accepte les octets sans zéro initial (« 0:1a:2:… », macOS).
func parseLooseMAC(s string) (net.HardwareAddr, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return net.ParseMAC(s)
	}
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return net.ParseMAC(strings.Join(parts, ":"))
}

// Disposition de MIB_IPNET_ROW2 (netioapi.h), 88 octets en x64 :
//
//	0  SOCKADDR_INET Address (28)   28 NET_IFINDEX InterfaceIndex
//	32 NET_LUID InterfaceLuid       40 UCHAR PhysicalAddress[32]
//	72 ULONG PhysicalAddressLength  76 NL_NEIGHBOR_STATE State
//	80 UCHAR Flags                  84 ULONG ReachabilityTime
const (
	ipnetRow2Size   = 88
	ipnetTable2Head = 8 // ULONG NumEntries + alignement sur 8
	nlnsIncomplete  = 1 // NlnsUnreachable = 0, NlnsIncomplete = 1
	afInet          = 2
)

// parseIPNetRow2 décode une ligne MIB_IPNET_ROW2. Indépendante de l'OS pour
// pouvoir être testée partout.
func parseIPNetRow2(b []byte) (Neighbor, bool) {
	if len(b) < ipnetRow2Size {
		return Neighbor{}, false
	}
	if binary.LittleEndian.Uint16(b[0:2]) != afInet {
		return Neighbor{}, false
	}
	if binary.LittleEndian.Uint32(b[76:80]) <= nlnsIncomplete {
		return Neighbor{}, false
	}
	l := binary.LittleEndian.Uint32(b[72:76])
	if l != 6 {
		return Neighbor{}, false
	}
	mac := net.HardwareAddr(bytes.Clone(b[40:46]))
	if !validMAC(mac) {
		return Neighbor{}, false
	}
	ip := netip.AddrFrom4([4]byte(b[4:8]))
	idx := binary.LittleEndian.Uint32(b[28:32])
	n := Neighbor{IP: ip, MAC: mac}
	if i, err := net.InterfaceByIndex(int(idx)); err == nil {
		n.Interface = i.Name
	}
	return n, true
}
