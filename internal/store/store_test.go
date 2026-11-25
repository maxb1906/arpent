package store

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/maxb1906/arpent/internal/audit"
	"github.com/maxb1906/arpent/internal/discovery"
	"github.com/maxb1906/arpent/internal/probe"
)

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Pharmacie X":            "pharmacie-x",
		"  Café de l'Église  ":   "cafe-de-l-eglise",
		"Garage Müller & Fils!!": "garage-muller-fils",
		"!!!":                    "",
	}
	for in, want := range cases {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, attendu %q", in, got, want)
		}
	}
}

func sample(mac string, port int, title string) *audit.Result {
	m, _ := net.ParseMAC(mac)
	now := time.Now()
	return &audit.Result{
		Started: now.Add(-time.Minute), Finished: now, Profile: "standard",
		Hosts: []audit.Host{{
			Host: discovery.Host{IP: netip.MustParseAddr("192.168.1.10"), MAC: m, Vendor: "QNAP", Names: []string{"nas.lan"}, Methods: []string{"arp"}},
			Ports: []audit.Port{{Port: port, Proto: "tcp", Service: probe.Service{Name: "http", HTTP: &probe.HTTPInfo{Status: 200, Title: title}}},
				{Port: 161, Proto: "udp", Service: probe.Service{Name: "snmp"}, Response: []byte{0x30, 0x01}}},
		}, {
			Host: discovery.Host{IP: netip.MustParseAddr("192.168.1.2"), Methods: []string{"tcp"}},
		}},
	}
}

func TestSiteLifecycle(t *testing.T) {
	data := t.TempDir()
	s, err := CreateSite(data, "Pharmacie X")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authorized(); ok {
		t.Error("autorisation présente sur un site neuf")
	}
	id1, err := s.BeginAudit(AuditMeta{Profile: "standard", Technician: "Tech", AuthorizedAt: time.Now(), AuthorizedBy: "Tech"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteAudit(id1, sample("24:5e:be:00:00:01", 8080, "QTS"), func(audit.Host) string { return "nas" }); err != nil {
		t.Fatal(err)
	}
	id2, _ := s.BeginAudit(AuditMeta{Profile: "quick"})
	if err := s.CompleteAudit(id2, sample("24:5e:be:00:00:01", 443, "QTS 5"), nil); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = OpenSite(data, "pharmacie-x")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if at, ok := s.Authorized(); !ok || at.IsZero() {
		t.Error("autorisation perdue")
	}
	audits, err := s.Audits()
	if err != nil || len(audits) != 2 || audits[0].ID != id2 || audits[0].Devices != 2 || audits[0].Ports != 2 {
		t.Fatalf("audits : %+v %v", audits, err)
	}
	if latest, _ := s.LatestAudit(); latest != id2 {
		t.Errorf("dernier audit %d", latest)
	}
	if prev, _ := s.PreviousAudit(id2); prev != id1 {
		t.Errorf("audit précédent %d", prev)
	}

	obs, err := s.Observations(id2)
	if err != nil || len(obs) != 2 {
		t.Fatalf("%+v %v", obs, err)
	}
	if obs[0].IP != "192.168.1.2" || obs[1].IP != "192.168.1.10" {
		t.Errorf("tri par IP : %s %s", obs[0].IP, obs[1].IP)
	}
	nas := obs[1]
	if nas.Vendor != "QNAP" || nas.Names[0] != "nas.lan" || len(nas.Services) != 2 {
		t.Fatalf("%+v", nas)
	}
	if nas.Services[0].Key() != "443/tcp" || nas.Services[0].Details.HTTP.Title != "QTS 5" || nas.Services[1].Raw[0] != 0x30 {
		t.Errorf("services : %+v", nas.Services)
	}
	// Même MAC → même appareil sur les deux audits.
	if nas.Device.FirstAudit != id1 || nas.Device.LastAudit != id2 {
		t.Errorf("appareil : %+v", nas.Device)
	}
	hist, _ := s.DeviceHistory(nas.Device.ID)
	if len(hist) != 2 || hist[0].DeviceType != "nas" {
		t.Errorf("historique : %+v", hist)
	}

	if err := s.Annotate(nas.Device.ID, " NAS compta ", "Bureau", "Compta", ""); err != nil {
		t.Fatal(err)
	}
	s.SetKnown(nas.Device.ID, true)
	d, _ := s.GetDevice(nas.Device.ID)
	if d.Label != "NAS compta" || !d.Known || d.KnownAt.IsZero() {
		t.Errorf("%+v", d)
	}

	sites, err := ListSites(data)
	if err != nil || len(sites) != 1 || sites[0].Name != "Pharmacie X" || sites[0].Audits != 2 {
		t.Errorf("%+v %v", sites, err)
	}
	if _, err := OpenSite(data, "inconnu"); err == nil {
		t.Error("site inexistant ouvert")
	}
}
