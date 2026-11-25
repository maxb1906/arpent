package rawnet

import (
	"bytes"
	"net"
	"net/netip"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var bcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

var serOpts = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

// ARPRequest construit une requête ARP « qui a dst ? » diffusée.
func ARPRequest(ifc Iface, dst netip.Addr) []byte {
	eth := &layers.Ethernet{SrcMAC: ifc.MAC, DstMAC: bcast, EthernetType: layers.EthernetTypeARP}
	s4, d4 := ifc.IP.As4(), dst.As4()
	arp := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
		Operation: layers.ARPRequest, SourceHwAddress: ifc.MAC, SourceProtAddress: s4[:], DstHwAddress: make([]byte, 6), DstProtAddress: d4[:]}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, serOpts, eth, arp)
	return buf.Bytes()
}

// ARPSender renvoie l'émetteur d'une trame ARP (requête ou réponse).
func ARPSender(frame []byte) (netip.Addr, net.HardwareAddr, uint16, bool) {
	p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)
	l, ok := p.Layer(layers.LayerTypeARP).(*layers.ARP)
	if !ok || len(l.SourceProtAddress) != 4 || len(l.SourceHwAddress) != 6 {
		return netip.Addr{}, nil, 0, false
	}
	ip := netip.AddrFrom4([4]byte(l.SourceProtAddress))
	if ip.IsUnspecified() {
		return netip.Addr{}, nil, 0, false
	}
	return ip, net.HardwareAddr(bytes.Clone(l.SourceHwAddress)), l.Operation, true
}

// SYN construit un segment TCP SYN.
func SYN(ifc Iface, dstMAC net.HardwareAddr, dst netip.Addr, srcPort, dstPort uint16, seq uint32) []byte {
	eth := &layers.Ethernet{SrcMAC: ifc.MAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: ifc.IP.AsSlice(), DstIP: dst.AsSlice(), Flags: layers.IPv4DontFragment}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), Seq: seq, SYN: true, Window: 1024,
		Options: []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}}}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, serOpts, eth, ip, tcp)
	return buf.Bytes()
}

// TCPReply décrit une réponse TCP à un SYN.
type TCPReply struct {
	From   netip.Addr
	Port   uint16 // port distant (celui sondé)
	ToPort uint16 // notre port source
	Ack    uint32
	SYNACK bool // ouvert
	RST    bool // fermé
}

// ParseTCPReply lit une trame IPv4/TCP adressée à ourIP.
func ParseTCPReply(frame []byte, ourIP netip.Addr) (TCPReply, bool) {
	p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)
	ip, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return TCPReply{}, false
	}
	dst, _ := netip.AddrFromSlice(ip.DstIP.To4())
	if dst != ourIP {
		return TCPReply{}, false
	}
	tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		return TCPReply{}, false
	}
	from, _ := netip.AddrFromSlice(ip.SrcIP.To4())
	return TCPReply{From: from, Port: uint16(tcp.SrcPort), ToPort: uint16(tcp.DstPort), Ack: tcp.Ack,
		SYNACK: tcp.SYN && tcp.ACK, RST: tcp.RST}, true
}

// DHCPInfo : ce qu'un client DHCP annonce de lui-même.
type DHCPInfo struct {
	MAC      net.HardwareAddr
	IP       netip.Addr // adresse demandée ou attribuée
	Hostname string     // option 12
	Vendor   string     // option 60 (ex. « android-dhcp-14 », « MSFT 5.0 »)
}

// ParseDHCP lit une trame DHCP (client → serveur ou réponse).
func ParseDHCP(frame []byte) (DHCPInfo, bool) {
	p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)
	d, ok := p.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	if !ok || len(d.ClientHWAddr) < 6 {
		return DHCPInfo{}, false
	}
	info := DHCPInfo{MAC: net.HardwareAddr(bytes.Clone(d.ClientHWAddr[:6]))}
	if ip, ok := netip.AddrFromSlice(d.YourClientIP.To4()); ok && !ip.IsUnspecified() {
		info.IP = ip
	} else if ip, ok := netip.AddrFromSlice(d.ClientIP.To4()); ok && !ip.IsUnspecified() {
		info.IP = ip
	}
	for _, o := range d.Options {
		switch o.Type {
		case layers.DHCPOptHostname:
			info.Hostname = printable(o.Data)
		case layers.DHCPOptClassID:
			info.Vendor = printable(o.Data)
		case layers.DHCPOptRequestIP:
			if len(o.Data) == 4 && !info.IP.IsValid() {
				info.IP = netip.AddrFrom4([4]byte(o.Data))
			}
		}
	}
	return info, true
}

// MDNSHost lit les enregistrements A d'une réponse mDNS (nom .local → IP).
func MDNSHost(frame []byte) (map[netip.Addr]string, bool) {
	p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)
	d, ok := p.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if !ok || !d.QR {
		return nil, false
	}
	out := map[netip.Addr]string{}
	for _, rr := range append(d.Answers, d.Additionals...) {
		if rr.Type == layers.DNSTypeA && len(rr.IP.To4()) == 4 {
			ip, _ := netip.AddrFromSlice(rr.IP.To4())
			out[ip] = strings.TrimSuffix(string(rr.Name), ".")
		}
	}
	return out, len(out) > 0
}

func printable(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		}
	}
	return strings.TrimSpace(sb.String())
}
