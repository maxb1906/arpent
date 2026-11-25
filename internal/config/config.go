package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName est le fichier de préférences dans le dossier de données.
const FileName = "config.yaml"

// Config : préférences de l'utilisateur (arpent-data/config.yaml).
type Config struct {
	Technician     string `yaml:"technician"`      // nom par défaut du technicien
	Lang           string `yaml:"lang"`            // langue de l'interface (vide : système)
	ReportLang     string `yaml:"report_lang"`     // langue par défaut des rapports (vide : interface)
	DefaultProfile string `yaml:"default_profile"` // quick, standard, full
	Rate           int    `yaml:"rate"`            // sondes par seconde (0 : défauts)
	Issuer         Issuer `yaml:"issuer"`          // émetteur des rapports
	// ReminderDays : fréquence d'audit souhaitée par défaut (0 : aucune).
	ReminderDays int `yaml:"reminder_days"`
}

// Issuer : profil de l'émetteur des rapports (§ 11.2).
type Issuer struct {
	Name    string `yaml:"name"`
	Company string `yaml:"company"`
	Contact string `yaml:"contact"` // adresse, téléphone, courriel…
	Legal   string `yaml:"legal"`   // mentions légales en pied de rapport
	Color   string `yaml:"color"`   // couleur principale, ex. #1f5f8b
	Logo    string `yaml:"logo"`    // image relative au dossier de données
}

// Default renvoie la configuration par défaut.
func Default() Config { return Config{DefaultProfile: "standard"} }

// Load lit dataDir/config.yaml ; un fichier absent donne la configuration par défaut.
func Load(dataDir string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(filepath.Join(dataDir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Default(), err
	}
	c.normalize()
	return c, nil
}

func (c *Config) normalize() {
	c.Technician = strings.TrimSpace(c.Technician)
	switch c.DefaultProfile {
	case "quick", "standard", "full":
	default:
		c.DefaultProfile = "standard"
	}
	if c.Rate < 0 {
		c.Rate = 0
	}
	if c.ReminderDays < 0 {
		c.ReminderDays = 0
	}
	if col := strings.TrimSpace(c.Issuer.Color); col != "" && !validColor(col) {
		c.Issuer.Color = ""
	}
	// Le logo doit rester dans le dossier de données (portable).
	if l := filepath.ToSlash(c.Issuer.Logo); filepath.IsAbs(c.Issuer.Logo) || strings.HasPrefix(l, "../") || strings.Contains(l, "/../") {
		c.Issuer.Logo = ""
	}
}

func validColor(s string) bool {
	if len(s) != 7 || s[0] != '#' {
		return false
	}
	for _, r := range s[1:] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

// Save écrit la configuration (avec un en-tête explicatif).
func Save(dataDir string, c Config) error {
	c.normalize()
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	head := "# Préférences d'Arpent / Arpent preferences — modifiable depuis l'interface (Réglages).\n"
	path := filepath.Join(dataDir, FileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(head), b...), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
