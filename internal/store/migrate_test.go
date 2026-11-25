package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// Une base créée au schéma 1 doit être migrée sans perte.
func TestMigrateFromV1(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sites", "ancien")
	os.MkdirAll(dir, 0o755)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(dir, "site.db")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(migrations[0] + `PRAGMA user_version = 1;
		INSERT INTO site (id, name, slug, created_at) VALUES (1, 'Ancien', 'ancien', '2026-01-01T00:00:00Z');
		INSERT INTO audit (id, started_at, status, profile) VALUES (1, '2026-01-01T00:00:00Z', 'done', 'quick');
		INSERT INTO device (id, identity) VALUES (1, 'ip:10.0.0.1');
		INSERT INTO observation (audit_id, device_id, ip) VALUES (1, 1, '10.0.0.1');`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := OpenSite(filepath.Dir(filepath.Dir(dir)), "ancien")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var v int
	s.DB().QueryRow("PRAGMA user_version").Scan(&v)
	if v != len(migrations) {
		t.Errorf("version %d, attendu %d", v, len(migrations))
	}
	obs, err := s.Observations(1)
	if err != nil || len(obs) != 1 || obs[0].IP != "10.0.0.1" {
		t.Errorf("%+v %v", obs, err)
	}
}
