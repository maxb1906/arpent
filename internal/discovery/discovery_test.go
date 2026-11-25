package discovery

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// Tests uniquement contre 127.0.0.0/8 : jamais de trafic hors de la machine.

func listen(t *testing.T) (int, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() { l.Close() }
}

func TestTCPAlive(t *testing.T) {
	port, stop := listen(t)
	defer stop()
	lo := netip.MustParseAddr("127.0.0.1")
	if _, ok := tcpAlive(context.Background(), lo, port, time.Second); !ok {
		t.Error("port ouvert non détecté")
	}
	// Port fermé : la connexion est refusée, l'hôte est donc bien vivant.
	closed, stop2 := listen(t)
	stop2()
	if _, ok := tcpAlive(context.Background(), lo, closed, time.Second); !ok {
		t.Error("refus de connexion non interprété comme hôte vivant")
	}
}

func TestRunLoopback(t *testing.T) {
	port, stop := listen(t)
	defer stop()
	targets := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	var calls int
	hosts, err := Run(context.Background(), targets, Options{
		Ports:       []int{port},
		NoICMP:      true,
		NoActiveARP: true,
		Local:       []netip.Prefix{},
		Progress:    func(done, total int) { calls++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].Methods[0] != MethodTCP {
		t.Fatalf("hôtes : %+v", hosts)
	}
	if calls != 1 {
		t.Errorf("progression appelée %d fois", calls)
	}
}

func TestRunCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Run(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Options{NoICMP: true, NoDNS: true, Local: []netip.Prefix{}})
	if err == nil {
		t.Error("annulation ignorée")
	}
}

func TestPingLoopback(t *testing.T) {
	if !pingAvailable() {
		t.Skip("ICMP non privilégié indisponible sur cette machine")
	}
	if _, ok := ping(context.Background(), netip.MustParseAddr("127.0.0.1"), time.Second); !ok {
		t.Error("pas de réponse ICMP de 127.0.0.1")
	}
}
