package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSave(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(dir)
	if err != nil || c.DefaultProfile != "standard" {
		t.Fatalf("%+v %v", c, err)
	}
	c.Technician = "  Max  "
	c.Issuer.Color = "#12abEF"
	c.Issuer.Logo = "../../etc/passwd"
	c.DefaultProfile = "bizarre"
	if err := Save(dir, c); err != nil {
		t.Fatal(err)
	}
	c2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Technician != "Max" || c2.Issuer.Color != "#12abEF" || c2.Issuer.Logo != "" || c2.DefaultProfile != "standard" {
		t.Errorf("%+v", c2)
	}
	os.WriteFile(filepath.Join(dir, FileName), []byte("technician: [\n"), 0o644)
	if _, err := Load(dir); err == nil {
		t.Error("YAML invalide accepté")
	}
}

func TestDataDir(t *testing.T) {
	d := filepath.Join(t.TempDir(), "x", "arpent-data")
	got, err := DataDir(d)
	if err != nil || got != d {
		t.Fatalf("%q %v", got, err)
	}
	t.Setenv("ARPENT_DATA", d+"2")
	if got, _ := DataDir(""); got != d+"2" {
		t.Errorf("ARPENT_DATA ignoré : %q", got)
	}
}
