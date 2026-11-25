package engine

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/maxb1906/arpent/internal/audit"
	"github.com/maxb1906/arpent/internal/store"
)

func TestRunSavesFindings(t *testing.T) {
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
			c.Write([]byte("220 (vsFTPd 2.3.4)\r\n"))
			time.Sleep(100 * time.Millisecond)
			c.Close()
		}
	}()
	audit.SetTestPorts([]int{l.Addr().(*net.TCPAddr).Port})
	defer audit.SetTestPorts(nil)

	s, err := store.CreateSite(t.TempDir(), "Test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := Begin(s, store.AuditMeta{Profile: "quick"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), s, id, audit.Options{
		Targets: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Profile: "quick", NoUDP: true, NoDiscovery: true,
	}); err != nil {
		t.Fatal(err)
	}
	fs, err := s.Findings(id)
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]bool{}
	for _, f := range fs {
		rules[f.Rule] = true
	}
	if !rules["ftp_plain"] || !rules["outdated"] {
		t.Errorf("points : %+v", fs)
	}
	a, _ := s.GetAudit(id)
	if a.Status != store.StatusDone {
		t.Errorf("statut %s", a.Status)
	}
}

func TestRunCancelled(t *testing.T) {
	s, _ := store.CreateSite(t.TempDir(), "Test")
	defer s.Close()
	id, _ := Begin(s, store.AuditMeta{Profile: "quick"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, s, id, audit.Options{Targets: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, NoDiscovery: true}); err == nil {
		t.Fatal("annulation ignorée")
	}
	if a, _ := s.GetAudit(id); a.Status != store.StatusCancelled {
		t.Errorf("statut %s", a.Status)
	}
}
