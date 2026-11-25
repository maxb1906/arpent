package portscan

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

var lo = netip.MustParseAddr("127.0.0.1")

func tcpListener(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func freePort(t *testing.T) int {
	t.Helper()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func TestScanTCPAndUDP(t *testing.T) {
	open1, open2, closed := tcpListener(t), tcpListener(t), freePort(t)

	// Service UDP qui ne répond qu'à la bonne sonde.
	uc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := uc.ReadFrom(buf)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				continue // Windows : WSAECONNRESET transitoire sur les sockets UDP
			}
			if bytes.Equal(buf[:n], []byte("ping")) {
				uc.WriteTo([]byte("pong"), from)
			}
		}
	}()
	udpPort := uc.LocalAddr().(*net.UDPAddr).Port
	closedUDP := freePort(t)

	res, err := Scan(context.Background(), []netip.Addr{lo}, Options{
		Ports:      []int{open1, closed, open2},
		UDP:        []UDPProbe{{Port: udpPort, Service: "test", Payload: []byte("ping")}, {Port: closedUDP, Payload: []byte("x")}},
		Timeout:    time.Second,
		UDPTimeout: 2 * time.Second, // Windows sous -race peut être lent
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("résultats : %+v", res)
	}
	if res[0].Proto != "tcp" || res[2].Proto != "udp" || res[2].Port != udpPort || string(res[2].Response) != "pong" {
		t.Errorf("résultats : %+v", res)
	}
	if !(res[0].Port < res[1].Port) {
		t.Error("résultats non triés")
	}
}

func TestProfiles(t *testing.T) {
	q, s, f := Quick.Ports(), Standard.Ports(), Full.Ports()
	if len(q) < 80 || len(q) > 120 {
		t.Errorf("rapide : %d ports", len(q))
	}
	if len(s) < 1000 || len(s) > 1600 {
		t.Errorf("standard : %d ports", len(s))
	}
	if len(f) != 65535 || f[0] != 1 || f[65534] != 65535 {
		t.Errorf("complet : %d ports", len(f))
	}
	set := map[int]bool{}
	for _, p := range s {
		if set[p] {
			t.Fatalf("doublon %d", p)
		}
		set[p] = true
	}
	for _, p := range q {
		if !set[p] {
			t.Errorf("port rapide %d absent du profil standard", p)
		}
	}
	for _, name := range []string{"rapide", "quick", "", "complet"} {
		if _, err := ParseProfile(name); err != nil {
			t.Error(err)
		}
	}
	if _, err := ParseProfile("x"); err == nil {
		t.Error("profil inconnu accepté")
	}
}

func TestUDPPayloads(t *testing.T) {
	// mDNS : en-tête 12 octets + nom + type PTR (12) + classe IN (1).
	m := dnsQuery(0, "_services._dns-sd._udp.local", 12, 1)
	if !bytes.HasSuffix(m, []byte{0, 0, 12, 0, 1}) || m[5] != 1 {
		t.Errorf("mDNS : % x", m)
	}
	nb := nbstatQuery()
	if len(nb) != 50 || nb[13] != 'C' || nb[14] != 'K' { // '*' = 0x2A → "CK"
		t.Errorf("NBSTAT : %d octets % x", len(nb), nb)
	}
	s := snmpGetSysDescr("public")
	if s[0] != 0x30 || int(s[1]) != len(s)-2 || !bytes.Contains(s, []byte("public")) {
		t.Errorf("SNMP : % x", s)
	}
}

func TestScanCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, []netip.Addr{lo}, Options{Ports: []int{1, 2, 3}}); err == nil {
		t.Error("annulation ignorée")
	}
}
