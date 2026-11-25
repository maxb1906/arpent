package rawnet

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// fakeNet simule un sous-réseau : des hôtes qui répondent à l'ARP et aux SYN.
type fakeNet struct {
	mu    sync.Mutex
	ifc   Iface
	hosts map[netip.Addr]net.HardwareAddr
	open  map[netip.Addr]map[uint16]bool
	inbox chan []byte
}

func newFake(ifc Iface) *fakeNet {
	return &fakeNet{ifc: ifc, hosts: map[netip.Addr]net.HardwareAddr{}, open: map[netip.Addr]map[uint16]bool{}, inbox: make(chan []byte, 10000)}
}

func (f *fakeNet) Close() error { return nil }

func (f *fakeNet) ReadPacket(d time.Duration) ([]byte, error) {
	select {
	case p := <-f.inbox:
		return p, nil
	case <-time.After(d):
		return nil, ErrTimeout
	}
}

func ser(ls ...gopacket.SerializableLayer) []byte {
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, serOpts, ls...)
	return buf.Bytes()
}

func (f *fakeNet) WritePacket(frame []byte) error {
	p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if a, ok := p.Layer(layers.LayerTypeARP).(*layers.ARP); ok && a.Operation == layers.ARPRequest {
		ip := netip.AddrFrom4([4]byte(a.DstProtAddress))
		if mac, ok := f.hosts[ip]; ok {
			f.inbox <- ser(&layers.Ethernet{SrcMAC: mac, DstMAC: f.ifc.MAC, EthernetType: layers.EthernetTypeARP},
				&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
					Operation: layers.ARPReply, SourceHwAddress: mac, SourceProtAddress: a.DstProtAddress, DstHwAddress: a.SourceHwAddress, DstProtAddress: a.SourceProtAddress})
		}
		return nil
	}
	ip4, _ := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp, _ := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if ip4 == nil || tcp == nil || !tcp.SYN {
		return nil
	}
	dst, _ := netip.AddrFromSlice(ip4.DstIP.To4())
	mac, ok := f.hosts[dst]
	if !ok {
		return nil
	}
	rip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: ip4.DstIP, DstIP: ip4.SrcIP}
	rt := &layers.TCP{SrcPort: tcp.DstPort, DstPort: tcp.SrcPort, Ack: tcp.Seq + 1, Seq: 99}
	if f.open[dst][uint16(tcp.DstPort)] {
		rt.SYN, rt.ACK = true, true
	} else {
		rt.RST, rt.ACK = true, true
	}
	rt.SetNetworkLayerForChecksum(rip)
	f.inbox <- ser(&layers.Ethernet{SrcMAC: mac, DstMAC: f.ifc.MAC, EthernetType: layers.EthernetTypeIPv4}, rip, rt)
	return nil
}

func testIfc() Iface {
	return Iface{Name: "test0", MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, IP: netip.MustParseAddr("192.168.50.2"), Prefix: netip.MustParsePrefix("192.168.50.0/24")}
}

func TestARPSweepAndSYNScan(t *testing.T) {
	ifc := testIfc()
	f := newFake(ifc)
	a, b := netip.MustParseAddr("192.168.50.10"), netip.MustParseAddr("192.168.50.20")
	f.hosts[a] = net.HardwareAddr{0xb8, 0x27, 0xeb, 1, 2, 3}
	f.hosts[b] = net.HardwareAddr{0x24, 0x5e, 0xbe, 4, 5, 6}
	f.open[a] = map[uint16]bool{22: true}
	f.open[b] = map[uint16]bool{80: true, 443: true}

	var targets []netip.Addr
	for i := 1; i < 40; i++ {
		targets = append(targets, netip.AddrFrom4([4]byte{192, 168, 50, byte(i)}))
	}
	targets = append(targets, netip.MustParseAddr("10.0.0.1")) // hors sous-réseau : ignoré
	macs := ARPSweep(context.Background(), f, ifc, targets, 0, 300*time.Millisecond)
	if len(macs) != 2 || macs[a].String() != "b8:27:eb:01:02:03" {
		t.Fatalf("ARP : %v", macs)
	}
	open := SYNScan(context.Background(), f, ifc, macs, []int{21, 22, 80, 443, 3389}, 0, 300*time.Millisecond, nil)
	want := []OpenPort{{a, 22}, {b, 80}, {b, 443}}
	if len(open) != len(want) {
		t.Fatalf("SYN : %v", open)
	}
	for i := range want {
		if open[i] != want[i] {
			t.Errorf("SYN %d : %v, attendu %v", i, open[i], want[i])
		}
	}
}

func TestListenPassive(t *testing.T) {
	ifc := testIfc()
	f := newFake(ifc)
	phone := net.HardwareAddr{0xda, 0xa1, 0x19, 9, 9, 9}
	// Annonce ARP gratuite d'un appareil discret.
	f.inbox <- ser(&layers.Ethernet{SrcMAC: phone, DstMAC: bcast, EthernetType: layers.EthernetTypeARP},
		&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
			Operation: layers.ARPRequest, SourceHwAddress: phone, SourceProtAddress: []byte{192, 168, 50, 77}, DstHwAddress: make([]byte, 6), DstProtAddress: []byte{192, 168, 50, 1}})
	// Requête DHCP du même appareil, avec son nom.
	dhcp := &layers.DHCPv4{Operation: layers.DHCPOpRequest, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6, ClientHWAddr: phone,
		Options: []layers.DHCPOption{layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{3}),
			layers.NewDHCPOption(layers.DHCPOptHostname, []byte("Pixel-8")), layers.NewDHCPOption(layers.DHCPOptClassID, []byte("android-dhcp-14"))}}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4zero, DstIP: net.IPv4bcast}
	udp := &layers.UDP{SrcPort: 68, DstPort: 67}
	udp.SetNetworkLayerForChecksum(ip)
	f.inbox <- ser(&layers.Ethernet{SrcMAC: phone, DstMAC: bcast, EthernetType: layers.EthernetTypeIPv4}, ip, udp, dhcp)
	// Nos propres trames sont ignorées.
	f.inbox <- ARPRequest(ifc, netip.MustParseAddr("192.168.50.9"))

	seen := Listen(context.Background(), f, ifc, 400*time.Millisecond)
	if len(seen) != 1 {
		t.Fatalf("%+v", seen)
	}
	s := seen[0]
	if s.IP.String() != "192.168.50.77" || s.Hostname != "Pixel-8" || s.Vendor != "android-dhcp-14" || len(s.Sources) != 2 {
		t.Errorf("%+v", s)
	}
}

func TestCheckDoesNotPanic(t *testing.T) {
	st := Check()
	t.Logf("mode avancé : %+v", st)
	if !st.Available && st.Reason == "" {
		t.Error("indisponible sans raison")
	}
}
