package netinfo

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestParseProcNetARP(t *testing.T) {
	in := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.168.1.7      0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.9      0x1         0x2         00:00:00:00:00:00     *        eth0
192.168.1.20     0x1         0x6         AA:BB:CC:DD:EE:14     *        wlan0
`
	got, err := parseProcNetARP(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d entrées, attendu 2 : %v", len(got), got)
	}
	if got[0].IP.String() != "192.168.1.1" || got[0].MAC.String() != "aa:bb:cc:dd:ee:01" || got[0].Interface != "eth0" {
		t.Errorf("entrée 0 : %+v", got[0])
	}
	if got[1].Interface != "wlan0" || got[1].MAC.String() != "aa:bb:cc:dd:ee:14" {
		t.Errorf("entrée 1 : %+v", got[1])
	}
}

func TestParseArpAn(t *testing.T) {
	in := `? (192.168.1.1) at 0:11:22:3:44:55 on en0 ifscope [ethernet]
? (192.168.1.5) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
`
	got, err := parseArpAn(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d entrées : %v", len(got), got)
	}
	if got[0].MAC.String() != "00:11:22:03:44:55" || got[0].Interface != "en0" {
		t.Errorf("%+v", got[0])
	}
}

func row2(ip [4]byte, mac []byte, state uint32) []byte {
	b := make([]byte, ipnetRow2Size)
	binary.LittleEndian.PutUint16(b[0:], afInet)
	copy(b[4:8], ip[:])
	binary.LittleEndian.PutUint32(b[28:], 999999) // index inexistant
	copy(b[40:], mac)
	binary.LittleEndian.PutUint32(b[72:], uint32(len(mac)))
	binary.LittleEndian.PutUint32(b[76:], state)
	return b
}

func TestParseIPNetRow2(t *testing.T) {
	mac := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60}
	n, ok := parseIPNetRow2(row2([4]byte{192, 168, 1, 42}, mac, 5))
	if !ok || n.IP.String() != "192.168.1.42" || n.MAC.String() != "10:20:30:40:50:60" {
		t.Fatalf("ok=%v %+v", ok, n)
	}
	if _, ok := parseIPNetRow2(row2([4]byte{192, 168, 1, 43}, mac, nlnsIncomplete)); ok {
		t.Error("entrée incomplète acceptée")
	}
	if _, ok := parseIPNetRow2(row2([4]byte{192, 168, 1, 44}, make([]byte, 6), 5)); ok {
		t.Error("MAC nulle acceptée")
	}
}

func TestSuggestSubnets(t *testing.T) {
	pp := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	ifs := []Interface{
		{Name: "lo", Up: true, Loopback: true, Prefixes: []netip.Prefix{pp("127.0.0.1/8")}},
		{Name: "eth0", Up: true, Prefixes: []netip.Prefix{pp("192.168.1.20/24"), pp("169.254.3.4/16")}},
		{Name: "eth1", Up: true, Prefixes: []netip.Prefix{pp("10.1.2.3/8")}},
		{Name: "wlan0", Up: false, Prefixes: []netip.Prefix{pp("192.168.50.2/24")}},
		{Name: "docker0", Up: true, Prefixes: []netip.Prefix{pp("172.17.0.1/16")}},
		{Name: "eth2", Up: true, Prefixes: []netip.Prefix{pp("192.168.1.30/24")}},
	}
	got := SuggestSubnets(ifs)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if got[0].Prefix.String() != "10.1.2.0/24" || !got[0].Reduced {
		t.Errorf("%+v", got[0])
	}
	if got[1].Prefix.String() != "192.168.1.0/24" || got[1].Reduced || got[1].Interface != "eth0" {
		t.Errorf("%+v", got[1])
	}
}

func TestHostsAndRanges(t *testing.T) {
	if h := Hosts(netip.MustParsePrefix("192.168.1.77/24")); len(h) != 254 || h[0].String() != "192.168.1.1" || h[253].String() != "192.168.1.254" {
		t.Errorf("/24 : %d hôtes, %v…%v", len(h), h[0], h[len(h)-1])
	}
	if h := Hosts(netip.MustParsePrefix("10.0.0.4/31")); len(h) != 2 {
		t.Errorf("/31 : %v", h)
	}
	got, err := ParseRanges("192.168.1.10-12, 10.0.0.1 192.168.1.11 10.0.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	want := "192.168.1.10 192.168.1.11 192.168.1.12 10.0.0.1 10.0.1.1 10.0.1.2"
	var s []string
	for _, a := range got {
		s = append(s, a.String())
	}
	if strings.Join(s, " ") != want {
		t.Errorf("ParseRanges = %v", s)
	}
	for _, bad := range []string{"", "300.1.1.1", "10.0.0.0/8", "192.168.1.20-10", "fe80::1"} {
		if _, err := ParseRanges(bad); err == nil {
			t.Errorf("ParseRanges(%q) aurait dû échouer", bad)
		}
	}
}

func TestValidMAC(t *testing.T) {
	if validMAC(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) || validMAC(net.HardwareAddr{1, 2, 3}) {
		t.Error("MAC invalide acceptée")
	}
}
