package rules

import (
	"testing"
	"time"

	"github.com/maxb1906/arpent/internal/i18n"
	"github.com/maxb1906/arpent/internal/probe"
	"github.com/maxb1906/arpent/internal/store"
)

func TestEmbeddedRulesTranslated(t *testing.T) {
	b, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range Default() {
		for _, lang := range b.Languages() {
			tr := b.Translator(lang)
			for _, part := range []string{"title", "explain", "fix"} {
				k := "rule." + r.ID + "." + part
				if tr.T(k) == k {
					t.Errorf("%s : traduction manquante %s", lang, k)
				}
			}
		}
	}
}

func svc(port int, proto, name string, d probe.Service) store.Service {
	d.Name = name
	return store.Service{ID: int64(port), Port: port, Proto: proto, Name: name, Product: d.Product, Version: d.Version, Details: d}
}

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	obs := []store.Observation{{
		IP:     "192.168.1.1",
		Device: store.Device{ID: 7},
		Services: []store.Service{
			svc(23, "tcp", "telnet", probe.Service{}),
			svc(80, "tcp", "http", probe.Service{HTTP: &probe.HTTPInfo{Status: 200, Title: "Router Login", Server: "Boa/0.94.14rc21"}}),
			svc(8080, "tcp", "http", probe.Service{HTTP: &probe.HTTPInfo{Status: 200, Title: "Directory listing"}}),
			svc(443, "tcp", "https", probe.Service{TLS: &probe.TLSInfo{Version: "TLS 1.0", NotAfter: now.Add(10 * 24 * time.Hour), SelfSigned: true}, HTTP: &probe.HTTPInfo{Status: 200}}),
			svc(8443, "tcp", "https", probe.Service{TLS: &probe.TLSInfo{Version: "TLS 1.3", NotAfter: now.Add(-24 * time.Hour)}}),
			svc(22, "tcp", "ssh", probe.Service{Product: "OpenSSH", Version: "7.4", SSH: &probe.SSHInfo{Protocol: "1.99"}}),
			svc(3306, "tcp", "mysql", probe.Service{}),
			{ID: 161, Port: 161, Proto: "udp", Name: "snmp", Raw: []byte{0x30, 0x29, 0x02}},
			svc(445, "tcp", "smb", probe.Service{SMB: &probe.SMBInfo{SMBv1: true}}),
		},
	}}
	got := map[string]store.Finding{}
	for _, f := range Evaluate(Default(), obs, now) {
		got[f.Rule+"@"+f.Params["port"]] = f
	}
	want := []string{"telnet@23", "http_admin_plain@80", "outdated@80", "tls_expiring@443", "tls_self_signed@443",
		"tls_old@443", "tls_expired@8443", "ssh_v1@22", "outdated@22", "database_exposed@3306", "snmp_public@161", "smb_v1@445"}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("point attendu absent : %s", w)
		}
	}
	for k := range got {
		found := false
		for _, w := range want {
			found = found || k == w
		}
		if !found {
			t.Errorf("point inattendu : %s", k)
		}
	}
	if f := got["tls_expiring@443"]; f.Params["days"] != "10" || f.Level != Warning {
		t.Errorf("%+v", f)
	}
	if f := got["outdated@80"]; f.Params["product"] != "Boa" {
		t.Errorf("%+v", f)
	}
	if got["telnet@23"].Level != Critical || got["telnet@23"].DeviceID != 7 {
		t.Errorf("%+v", got["telnet@23"])
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		less bool
	}{
		{"7.4p1", "8.0", true}, {"8.9p1", "8.0", false}, {"2.4.41", "2.4.58", true}, {"2.4.58", "2.4.58", false},
		{"1.18.0", "1.22", true}, {"", "1.0", false}, {"2022.83", "2020.79", false},
	}
	for _, c := range cases {
		if got := VersionLess(c.a, c.b); got != c.less {
			t.Errorf("VersionLess(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestLoadInvalid(t *testing.T) {
	if _, err := Load([]byte("- id: x\n  level: grave\n")); err == nil {
		t.Error("niveau invalide accepté")
	}
	if _, err := Load([]byte("- level: info\n")); err == nil {
		t.Error("règle sans id acceptée")
	}
}
