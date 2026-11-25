package store

import (
	"archive/zip"
	"bytes"
	"testing"
	"time"
)

func exportBytes(t *testing.T, s *Site) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := s.Export(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func addAudit(t *testing.T, s *Site, mac string, port int) int64 {
	t.Helper()
	id, err := s.BeginAudit(AuditMeta{Profile: "standard", Ranges: "192.168.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteAudit(id, sample(mac, port, "QTS"), nil); err != nil {
		t.Fatal(err)
	}
	// Un point d'attention rattaché au service, pour vérifier la correspondance.
	obs, _ := s.Observations(id)
	for _, o := range obs {
		for _, sv := range o.Services {
			if sv.Port == port {
				s.SaveFindings(id, []Finding{{DeviceID: o.Device.ID, ServiceID: sv.ID, Rule: "test", Level: "warning", Params: map[string]string{"port": "x"}}})
			}
		}
	}
	return id
}

func TestExportImportMerge(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	a, _ := CreateSite(d1, "Pharmacie Export")
	defer a.Close()
	addAudit(t, a, "24:5e:be:00:00:01", 8080)
	time.Sleep(1100 * time.Millisecond) // dates d'audit distinctes (précision : la seconde)
	addAudit(t, a, "24:5e:be:00:00:01", 443)
	a.UpdateInfo("Rue de la Gare 1", "", "")

	// 1. Import dans un dossier vide : création.
	arc := exportBytes(t, a)
	res, err := Import(d2, bytes.NewReader(arc), int64(len(arc)))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.Added != 2 || res.Slug != "pharmacie-export" {
		t.Fatalf("%+v", res)
	}
	b, err := OpenSite(d2, "pharmacie-export")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if info, _ := b.Info(); info.Address != "Rue de la Gare 1" {
		t.Errorf("fiche : %+v", info)
	}

	// 2. Nouvel audit côté B, annotation, puis retour vers A : fusion.
	time.Sleep(1100 * time.Millisecond)
	idB := addAudit(t, b, "24:5e:be:00:00:01", 22)
	obs, _ := b.Observations(idB)
	b.Annotate(obs[len(obs)-1].Device.ID, "NAS compta", "", "", "")
	arc = exportBytes(t, b)
	res, err = Import(d1, bytes.NewReader(arc), int64(len(arc)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Created || res.Added != 1 || res.Skipped != 2 {
		t.Fatalf("fusion : %+v", res)
	}
	ids, _ := a.DoneAuditsChrono()
	if len(ids) != 3 {
		t.Fatalf("%d audits", len(ids))
	}
	last := ids[2]
	obs, _ = a.Observations(last)
	if len(obs) != 2 || obs[1].Device.Label != "NAS compta" || obs[1].Services[0].Port != 22 {
		t.Errorf("observations fusionnées : %+v", obs)
	}
	fs, _ := a.Findings(last)
	if len(fs) != 1 || fs[0].Port != 22 {
		t.Errorf("points fusionnés : %+v", fs)
	}
	// Réimporter ne duplique rien.
	res, _ = Import(d1, bytes.NewReader(arc), int64(len(arc)))
	if res.Added != 0 || res.Skipped != 3 {
		t.Errorf("réimport : %+v", res)
	}
}

func TestImportRejects(t *testing.T) {
	d := t.TempDir()
	if _, err := Import(d, bytes.NewReader([]byte("pas un zip")), 10); err == nil {
		t.Error("fichier quelconque accepté")
	}
	// Archive sans manifeste.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("site.db")
	w.Write([]byte("x"))
	zw.Close()
	if _, err := Import(d, bytes.NewReader(buf.Bytes()), int64(buf.Len())); err == nil {
		t.Error("archive sans manifeste acceptée")
	}
	// Chemin malveillant dans les rapports : ignoré.
	s, _ := CreateSite(t.TempDir(), "Slip")
	defer s.Close()
	arc := exportBytes(t, s)
	zr, _ := zip.NewReader(bytes.NewReader(arc), int64(len(arc)))
	buf.Reset()
	zw = zip.NewWriter(&buf)
	for _, f := range zr.File {
		w, _ := zw.Create(f.Name)
		rc, _ := f.Open()
		var b bytes.Buffer
		b.ReadFrom(rc)
		w.Write(b.Bytes())
	}
	w, _ = zw.Create("rapports/../../evil.txt")
	w.Write([]byte("evil"))
	zw.Close()
	res, err := Import(d, bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil || res.Reports != 0 {
		t.Errorf("%+v %v", res, err)
	}
}

func TestSearch(t *testing.T) {
	d := t.TempDir()
	s, _ := CreateSite(d, "Garage")
	addAudit(t, s, "24:5e:be:00:00:01", 8080)
	s.Close()
	s2, _ := CreateSite(d, "Cabinet")
	addAudit(t, s2, "24:5e:be:00:00:09", 443)
	s2.Close()
	cases := map[string]int{"QNAP": 2, "24-5e-be-00-00-09": 1, "nas.lan": 2, "snmp": 2, "test": 2, "x": 0, "introuvable": 0}
	for q, want := range cases {
		hits, err := Search(d, q)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != want {
			t.Errorf("%q : %d résultats, attendu %d (%+v)", q, len(hits), want, hits)
		}
	}
}
