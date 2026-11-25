package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/maxb1906/arpent/internal/audit"
	"github.com/maxb1906/arpent/internal/diff"
	"github.com/maxb1906/arpent/internal/discovery"
	"github.com/maxb1906/arpent/internal/i18n"
	"github.com/maxb1906/arpent/internal/probe"
	"github.com/maxb1906/arpent/internal/rules"
	"github.com/maxb1906/arpent/internal/store"
)

func result(extraPort bool) *audit.Result {
	mac, _ := net.ParseMAC("24:5e:be:00:00:01")
	now := time.Now()
	h := audit.Host{
		Host: discovery.Host{IP: netip.MustParseAddr("192.168.1.10"), MAC: mac, Vendor: "QNAP Systems, Inc.", Names: []string{"nas.lan"}},
		Ports: []audit.Port{
			{Port: 23, Proto: "tcp", Service: probe.Service{Name: "telnet"}},
			{Port: 443, Proto: "tcp", Service: probe.Service{Name: "https", TLS: &probe.TLSInfo{Version: "TLS 1.2", Subject: "nas", NotAfter: now.Add(-48 * time.Hour), SelfSigned: true, SHA256: "abcdef0123456789"}, HTTP: &probe.HTTPInfo{Status: 200, Title: "QTS <login>"}}},
		},
	}
	if extraPort {
		h.Ports = append(h.Ports, audit.Port{Port: 3389, Proto: "tcp", Service: probe.Service{Name: "rdp"}})
	}
	return &audit.Result{Started: now.Add(-time.Minute), Finished: now, Profile: "standard", Hosts: []audit.Host{h,
		{Host: discovery.Host{IP: netip.MustParseAddr("192.168.1.2")}}}}
}

func site(t *testing.T) (*store.Site, int64) {
	t.Helper()
	s, err := store.CreateSite(t.TempDir(), "Pharmacie Él")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for i, extra := range []bool{false, true} {
		id, _ := s.BeginAudit(store.AuditMeta{Profile: "standard", Ranges: "192.168.1.0/24", Technician: "Max", AuthorizedAt: time.Now()})
		if err := s.CompleteAudit(id, result(extra), nil); err != nil {
			t.Fatal(err)
		}
		if err := rules.Apply(s, id); err != nil {
			t.Fatal(err)
		}
		if err := diff.Apply(s, id); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			return s, id
		}
	}
	return nil, 0
}

var rawKey = regexp.MustCompile(`\b(report|web|rule|level|change|col|profile|type|scan)\.[a-z_.\-]+\b`)

func TestHTML(t *testing.T) {
	s, id := site(t)
	d, err := Build(s, id, "Arpent test")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := i18n.Default()
	for _, lang := range []string{"fr", "en"} {
		var buf bytes.Buffer
		if err := HTML(&buf, d, b.Translator(lang)); err != nil {
			t.Fatal(err)
		}
		html := buf.String()
		body := regexp.MustCompile(`(?s)<style>.*?</style>`).ReplaceAllString(html, "")
		for _, m := range rawKey.FindAllString(body, -1) {
			if m != "report.css" {
				t.Errorf("%s : clé non traduite %q", lang, m)
			}
		}
		for _, want := range []string{"Pharmacie Él", "192.168.1.10", "QTS &lt;login&gt;", "<style>"} {
			if !strings.Contains(html, want) {
				t.Errorf("%s : %q absent", lang, want)
			}
		}
		if regexp.MustCompile(`(src|href)="https?:`).MatchString(html) {
			t.Errorf("%s : ressource externe dans un rapport censé être autonome", lang)
		}
	}
	if d.Risk() != "high" || d.Previous == nil || d.ChangeCounts["port_opened"] != 1 {
		t.Errorf("risque %s, précédent %v, changements %v", d.Risk(), d.Previous, d.ChangeCounts)
	}
	groups := d.Groups()
	if len(groups) == 0 || groups[0].Rule != "telnet" {
		t.Errorf("groupes : %+v", groups)
	}
}

func TestCSVAndJSON(t *testing.T) {
	s, id := site(t)
	d, _ := Build(s, id, "Arpent test")
	b, _ := i18n.Default()

	var buf bytes.Buffer
	if err := CSV(&buf, d, b.Translator("fr")); err != nil {
		t.Fatal(err)
	}
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(buf.String(), "\xef\xbb\xbf")))
	r.Comma = ';'
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	// En-tête + 3 services du NAS + 1 ligne pour l'appareil sans service.
	if len(rows) != 5 || rows[0][0] != "IP" {
		t.Errorf("CSV : %d lignes %v", len(rows), rows)
	}

	buf.Reset()
	if err := JSON(&buf, d, b.Translator("en")); err != nil {
		t.Fatal(err)
	}
	var j map[string]any
	if err := json.Unmarshal(buf.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	if len(j["devices"].([]any)) != 2 || len(j["findings"].([]any)) == 0 {
		t.Errorf("JSON : %v", j)
	}
	f0 := j["findings"].([]any)[0].(map[string]any)
	if f0["rule"] != "telnet" || !strings.Contains(f0["title"].(string), "Telnet open") {
		t.Errorf("JSON finding : %v", f0)
	}
}

func TestBuildRunning(t *testing.T) {
	s, _ := store.CreateSite(t.TempDir(), "X")
	defer s.Close()
	id, _ := s.BeginAudit(store.AuditMeta{Profile: "quick"})
	if _, err := Build(s, id, ""); err == nil {
		t.Error("rapport d'un audit en cours accepté")
	}
}
