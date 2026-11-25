package audit

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/maxb1906/arpent/internal/portscan"
)

func TestRunLoopback(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			time.Sleep(100 * time.Millisecond)
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	// Profil rapide : on remplace la liste par le seul port de test.
	phases := map[string]bool{}
	res, err := runWithPorts(context.Background(), []int{port}, func(p string, d, t int) { phases[p] = true })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 || len(res.Hosts[0].Ports) != 1 || res.Hosts[0].Ports[0].Service.Name != "ssh" {
		t.Fatalf("%+v", res.Hosts)
	}
	if !phases[PhasePorts] || !phases[PhaseProbes] {
		t.Errorf("phases : %v", phases)
	}
}

// runWithPorts : comme Run mais avec une liste de ports imposée (test).
func runWithPorts(ctx context.Context, ports []int, prog func(string, int, int)) (*Result, error) {
	saved := testPorts
	testPorts = ports
	defer func() { testPorts = saved }()
	return Run(ctx, Options{
		Targets:     []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Profile:     portscan.Quick,
		NoUDP:       true,
		NoDiscovery: true,
		Progress:    prog,
	})
}
