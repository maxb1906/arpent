package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/maxb1906/arpent/internal/i18n"
)

type harness struct {
	t      *testing.T
	srv    *Server
	client *http.Client
	base   string
}

func start(t *testing.T) *harness {
	t.Helper()
	b, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{DataDir: t.TempDir(), Bundle: b, Lang: "fr", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	jar, _ := cookiejar.New(nil)
	h := &harness{t: t, srv: srv, client: &http.Client{Jar: jar, Timeout: 30 * time.Second}, base: "http://" + srv.Addr()}
	return h
}

// wait attend la fin de l'audit auditPath.
func (h *harness) wait(auditPath string) {
	h.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, js := h.get("/api" + auditPath + "/progress")
		var snap jobSnapshot
		json.Unmarshal([]byte(js), &snap)
		if snap.Status != "running" {
			if snap.Status != "done" {
				h.t.Fatalf("audit : %+v", snap)
			}
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatal("audit trop long")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (h *harness) get(path string) (int, string) {
	h.t.Helper()
	resp, err := h.client.Get(h.base + path)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (h *harness) post(path string, form url.Values) (int, string, string) {
	h.t.Helper()
	resp, err := h.client.PostForm(h.base+path, form)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Request.URL.Path, string(b)
}

var rawKey = regexp.MustCompile(`\b(web|cmd|flag|col|phase|status|profile|legal|type|scan|change|rule|level)\.[a-z_.\-]+\b`)

func noRawKeys(t *testing.T, page, body string) {
	t.Helper()
	// Ignore les noms de fichiers (app.js, app.css) et les URLs.
	for _, m := range rawKey.FindAllString(body, -1) {
		t.Errorf("%s : clé non traduite %q", page, m)
	}
}

func TestSecurity(t *testing.T) {
	h := start(t)
	// Sans session.
	if code, _ := h.get("/"); code != http.StatusUnauthorized {
		t.Errorf("sans jeton : %d", code)
	}
	if code, _ := h.get("/login?k=faux"); code != http.StatusUnauthorized {
		t.Errorf("mauvais jeton : %d", code)
	}
	// Mauvais Host (DNS rebinding).
	req, _ := http.NewRequest("GET", h.base+"/", nil)
	req.Host = "evil.example:80"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("hôte étranger : %d", resp.StatusCode)
	}
	// Avec session, mais POST depuis une autre origine.
	if code, _ := h.get(strings.TrimPrefix(h.srv.URL(), h.base)); code != 200 {
		t.Fatalf("login : %d", code)
	}
	req, _ = http.NewRequest("POST", h.base+"/sites", strings.NewReader("name=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://evil.example")
	resp, err = h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("origine étrangère : %d", resp.StatusCode)
	}
	if !strings.HasPrefix(h.srv.Addr(), "127.0.0.1:") {
		t.Errorf("écoute hors boucle locale : %s", h.srv.Addr())
	}
}

func TestAuditFlow(t *testing.T) {
	h := start(t)
	h.get(strings.TrimPrefix(h.srv.URL(), h.base))

	code, body := h.get("/")
	if code != 200 || !strings.Contains(body, "Nouveau site") {
		t.Fatalf("accueil : %d", code)
	}
	noRawKeys(t, "accueil", body)

	code, path, body := h.post("/sites", url.Values{"name": {"Pharmacie Test"}})
	if code != 200 || path != "/sites/pharmacie-test" {
		t.Fatalf("création : %d %s", code, path)
	}
	noRawKeys(t, "site", body)

	// Sans confirmation d'autorisation : refus.
	_, path, body = h.post("/sites/pharmacie-test/audits", url.Values{"ranges": {"127.0.0.1"}, "profile": {"quick"}})
	if !strings.Contains(body, "confirmer être autorisé") {
		t.Errorf("autorisation non exigée : %s", path)
	}
	_, path, _ = h.post("/sites/pharmacie-test/audits", url.Values{"ranges": {"127.0.0.1"}, "profile": {"quick"}, "authorized": {"1"}, "technician": {"Max"}, "no_udp": {"1"}})
	if !strings.HasPrefix(path, "/sites/pharmacie-test/audits/") {
		t.Fatalf("lancement : %s", path)
	}
	auditPath := path
	h.wait(auditPath)
	code, body = h.get(auditPath)
	if code != 200 || !strings.Contains(body, "127.0.0.1") || !strings.Contains(body, "Inventaire") {
		t.Fatalf("page d'audit : %d", code)
	}
	noRawKeys(t, "audit", body)

	m := regexp.MustCompile(`/sites/pharmacie-test/devices/\d+\?audit=\d+`).FindString(body)
	if m == "" {
		t.Fatal("lien vers l'appareil absent")
	}
	code, body = h.get(m)
	if code != 200 || !strings.Contains(body, "Historique") {
		t.Errorf("fiche appareil : %d", code)
	}
	noRawKeys(t, "appareil", body)

	// Réglages : technicien et émetteur (avec logo) repris dans le rapport.
	code, body = h.get("/settings")
	if code != 200 || !strings.Contains(body, "Émetteur des rapports") {
		t.Fatalf("réglages : %d", code)
	}
	noRawKeys(t, "réglages", body)
	os.WriteFile(filepath.Join(h.srv.opt.DataDir, "logo.svg"), []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>`), 0o644)
	_, _, body = h.post("/settings", url.Values{"technician": {"Max Test"}, "default_profile": {"quick"}, "issuer_company": {"Réseaux & Co"},
		"issuer_logo": {"logo.svg"}, "issuer_color": {"#aa3300"}, "report_lang": {"en"}})
	if !strings.Contains(body, "Réglages enregistrés") {
		t.Error("réglages non enregistrés")
	}
	if !strings.Contains(body, `src="data:image/svg`) {
		i := strings.Index(body, "logo")
		t.Errorf("aperçu du logo absent : %s", body[i:min(len(body), i+600)])
	}
	code, body = h.get(auditPath + "/report?format=html")
	if !strings.Contains(body, "Réseaux &amp; Co") || !strings.Contains(body, "data:image/svg") || !strings.Contains(body, "--accent:#aa3300") {
		t.Errorf("émetteur absent du rapport : company=%v logo=%v color=%v", strings.Contains(body, "Réseaux &amp; Co"), strings.Contains(body, "data:image/svg"), strings.Contains(body, "--accent:#aa3300"))

	}
	if !strings.Contains(body, "Network audit report") {
		t.Error("langue de rapport par défaut (en) ignorée")
	}

	// Personnalisation du rapport et type « résumé direction ».
	h.post(auditPath+"/customize", url.Values{"comment": {"Synthèse de test du technicien."}})
	code, body = h.get(auditPath + "/report?format=html&kind=executive&lang=fr")
	if code != 200 || !strings.Contains(body, "Synthèse de test du technicien.") || !strings.Contains(body, "résumé direction") || strings.Contains(body, "Annexe technique") {
		t.Errorf("rapport personnalisé : %d", code)
	}

	// Rapport : affichage en anglais, export CSV, enregistrement dans le site.
	code, body = h.get(auditPath + "/report?lang=en&format=html")
	if code != 200 || !strings.Contains(body, "Network audit report") || !strings.Contains(body, "<style>") {
		t.Errorf("rapport HTML : %d", code)
	}
	resp, err := h.client.Get(h.base + auditPath + "/report?format=csv")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Content-Disposition"), ".csv") {
		t.Errorf("CSV : %v", resp.Header)
	}
	_, _, body = h.post(auditPath+"/report", url.Values{"format": {"html"}, "lang": {"fr"}})
	if !strings.Contains(body, "Rapport enregistré") || !strings.Contains(body, "rapports") {
		t.Error("rapport non enregistré")
	}

	// Annotation et validation de l'appareil.
	devPath := strings.SplitN(m, "?", 2)[0]
	_, _, body = h.post(devPath, url.Values{"label": {"Serveur devbox"}, "known": {"1"}, "back": {devPath}})
	if !strings.Contains(body, "Serveur devbox") || !strings.Contains(body, `name="known" value="1" checked`) {
		t.Error("annotation non enregistrée")
	}

	// Second audit : plus de confirmation demandée ; puis en anglais.
	h.post("/lang", url.Values{"lang": {"en"}, "back": {"/sites/pharmacie-test"}})
	code, body = h.get("/sites/pharmacie-test")
	if code != 200 || !strings.Contains(body, "New audit") || strings.Contains(body, `name="authorized"`) {
		t.Errorf("site en anglais : %d", code)
	}
	noRawKeys(t, "site (en)", body)
	// Second audit : évolution, comparaison, frise.
	_, path2, _ := h.post("/sites/pharmacie-test/audits", url.Values{"ranges": {"127.0.0.1"}, "profile": {"quick"}, "no_udp": {"1"}})
	h.wait(path2)
	code, body = h.get("/sites/pharmacie-test")
	if !strings.Contains(body, `<svg class="chart"`) || !strings.Contains(body, "Site evolution") {
		t.Errorf("graphiques d'évolution absents (%d)", code)
	}
	noRawKeys(t, "site (évolution)", body)
	code, body = h.get("/sites/pharmacie-test/compare")
	if code != 200 || !strings.Contains(body, "Changes from") {
		t.Errorf("comparaison : %d", code)
	}
	noRawKeys(t, "comparaison", body)
	code, body = h.get(devPath)
	if !strings.Contains(body, "Device timeline") || !strings.Contains(body, "First seen") {
		t.Errorf("frise absente (%d)", code)
	}
	noRawKeys(t, "frise", body)

	if code, body = h.get("/sites/inconnu"); code != 404 {
		t.Errorf("site inconnu : %d", code)
	}
}
