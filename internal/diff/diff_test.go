package diff

import (
	"testing"
	"time"

	"github.com/maxb1906/arpent/internal/probe"
	"github.com/maxb1906/arpent/internal/store"
)

func ob(dev int64, ip, mac string, svcs ...store.Service) store.Observation {
	return store.Observation{Device: store.Device{ID: dev}, IP: ip, MAC: mac, Services: svcs}
}

func sv(port int, name, product, version string) store.Service {
	return store.Service{Port: port, Proto: "tcp", Name: name, Product: product, Version: version}
}

func TestCompare(t *testing.T) {
	cert := func(sha string) store.Service {
		s := sv(443, "https", "", "")
		s.Details.TLS = &probe.TLSInfo{Subject: "nas", NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), SHA256: sha}
		return s
	}
	prev := []store.Observation{
		ob(1, "192.168.1.1", "aa:aa:aa:aa:aa:01", sv(80, "http", "", ""), sv(23, "telnet", "", "")),
		ob(2, "192.168.1.10", "aa:aa:aa:aa:aa:02", sv(22, "ssh", "OpenSSH", "8.9p1"), cert("1111111111111111")),
		ob(3, "192.168.1.20", "aa:aa:aa:aa:aa:03"),
		ob(4, "192.168.1.30", "aa:aa:aa:aa:aa:04"),
		ob(5, "10.0.0.5", "aa:aa:aa:aa:aa:05"), // hors des plages du nouvel audit
	}
	cur := []store.Observation{
		ob(1, "192.168.1.1", "aa:aa:aa:aa:aa:01", sv(80, "http", "", ""), sv(443, "https", "", "")),
		ob(2, "192.168.1.11", "aa:aa:aa:aa:aa:02", sv(22, "ssh", "OpenSSH", "9.6p1"), cert("2222222222222222")),
		ob(6, "192.168.1.30", "aa:aa:aa:aa:aa:06"), // même IP que l'appareil 4, autre MAC
		ob(7, "192.168.1.40", "aa:aa:aa:aa:aa:07"),
	}
	scope := ScopeFromRanges("192.168.1.0/24")
	got := map[string]int{}
	for _, c := range Compare(prev, cur, scope) {
		got[c.Kind]++
		switch {
		case c.Kind == store.ChangeIPChanged && (c.Before != "192.168.1.10" || c.After != "192.168.1.11"):
			t.Errorf("%+v", c)
		case c.Kind == store.ChangeServiceChanged && c.Field == "product" && c.After != "OpenSSH 9.6p1":
			t.Errorf("%+v", c)
		case c.Kind == store.ChangePortOpened && c.Port != 443:
			t.Errorf("%+v", c)
		case c.Kind == store.ChangePortClosed && c.Port != 23:
			t.Errorf("%+v", c)
		}
	}
	want := map[string]int{
		store.ChangeNewDevice: 2, store.ChangeGoneDevice: 2, store.ChangeIPChanged: 1, store.ChangeIPReassigned: 1,
		store.ChangePortOpened: 1, store.ChangePortClosed: 1, store.ChangeServiceChanged: 2,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s : %d, attendu %d (%v)", k, got[k], v, got)
		}
	}
	cs := Compare(prev, cur, scope)
	if cs[0].Kind != store.ChangeNewDevice {
		t.Errorf("tri : %s en premier", cs[0].Kind)
	}
}

func TestIdenticalAudits(t *testing.T) {
	a := []store.Observation{ob(1, "192.168.1.1", "m", sv(80, "http", "nginx", "1.24"))}
	if cs := Compare(a, a, nil); len(cs) != 0 {
		t.Errorf("%+v", cs)
	}
}
