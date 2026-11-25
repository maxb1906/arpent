// Package store conserve les audits dans une base SQLite par site
// (arpent-data/sites/<slug>/site.db), avec le driver pur Go modernc.org/sqlite.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"
	_ "modernc.org/sqlite"
)

// ErrNoSite : le site demandé n'existe pas.
var ErrNoSite = errors.New("site introuvable")

// TimeFormat est le format des dates stockées (UTC).
const TimeFormat = time.RFC3339

// Site est une base ouverte.
type Site struct {
	db   *sql.DB
	Dir  string // dossier du site
	Slug string
}

// SiteInfo décrit un site.
type SiteInfo struct {
	Name, Slug, Address, Contact, Notes string
	CreatedAt                           time.Time
}

// Slugify transforme un nom en nom de dossier : « Pharmacie Él X » → « pharmacie-el-x ».
func Slugify(name string) string {
	var sb strings.Builder
	dash := false
	for _, r := range norm.NFD.String(strings.ToLower(name)) {
		switch {
		case unicode.Is(unicode.Mn, r): // accents décomposés
		case r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)):
			sb.WriteRune(r)
			dash = false
		default:
			if !dash && sb.Len() > 0 {
				sb.WriteByte('-')
				dash = true
			}
		}
	}
	s := strings.TrimSuffix(sb.String(), "-")
	if len(s) > 60 {
		s = strings.TrimSuffix(s[:60], "-")
	}
	return s
}

// SitesDir renvoie le dossier des sites dans dataDir.
func SitesDir(dataDir string) string { return filepath.Join(dataDir, "sites") }

func open(dir string) (*sql.DB, error) {
	path := filepath.Join(dir, "site.db")
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite : un seul écrivain, évite les verrous
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("base créée par une version plus récente d'Arpent (schéma %d)", v)
	}
	for i := v; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d : %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// CreateSite crée (ou ouvre s'il existe) le site name dans dataDir.
func CreateSite(dataDir, name string) (*Site, error) {
	name = strings.TrimSpace(name)
	slug := Slugify(name)
	if slug == "" {
		return nil, errors.New("nom de site vide ou invalide")
	}
	dir := filepath.Join(SitesDir(dataDir), slug)
	if err := os.MkdirAll(filepath.Join(dir, "rapports"), 0o755); err != nil {
		return nil, err
	}
	db, err := open(dir)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`INSERT INTO site (id, name, slug, created_at) VALUES (1, ?, ?, ?) ON CONFLICT (id) DO NOTHING`,
		name, slug, time.Now().UTC().Format(TimeFormat))
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Site{db: db, Dir: dir, Slug: slug}, nil
}

// OpenSite ouvre un site existant, désigné par son nom ou son slug.
func OpenSite(dataDir, nameOrSlug string) (*Site, error) {
	slug := Slugify(nameOrSlug)
	dir := filepath.Join(SitesDir(dataDir), slug)
	if _, err := os.Stat(filepath.Join(dir, "site.db")); err != nil {
		return nil, fmt.Errorf("%w : %s", ErrNoSite, nameOrSlug)
	}
	db, err := open(dir)
	if err != nil {
		return nil, err
	}
	return &Site{db: db, Dir: dir, Slug: slug}, nil
}

// Close ferme la base.
func (s *Site) Close() error { return s.db.Close() }

// DB expose la base (tests, maintenance).
func (s *Site) DB() *sql.DB { return s.db }

// ReportsDir est le dossier des rapports du site.
func (s *Site) ReportsDir() string { return filepath.Join(s.Dir, "rapports") }

// Info lit la fiche du site.
func (s *Site) Info() (SiteInfo, error) {
	var i SiteInfo
	var created string
	err := s.db.QueryRow(`SELECT name, slug, address, contact, notes, created_at FROM site WHERE id = 1`).
		Scan(&i.Name, &i.Slug, &i.Address, &i.Contact, &i.Notes, &created)
	i.CreatedAt, _ = time.Parse(TimeFormat, created)
	return i, err
}

// UpdateInfo modifie l'adresse, le contact et les notes du site.
func (s *Site) UpdateInfo(address, contact, notes string) error {
	_, err := s.db.Exec(`UPDATE site SET address = ?, contact = ?, notes = ? WHERE id = 1`, address, contact, notes)
	return err
}

// SiteSummary résume un site pour le tableau de bord.
type SiteSummary struct {
	SiteInfo
	Audits       int
	LastAudit    time.Time
	LastID       int64
	Devices      int // dernier audit
	Critical     int // points critiques du dernier audit
	Warning      int
	PrevFindings int // critiques + attention de l'audit précédent (-1 : aucun)
	ReminderDays int // 0 : pas de rappel
	reminderSet  bool
}

// Findings renvoie critiques + attention du dernier audit.
func (s SiteSummary) Findings() int { return s.Critical + s.Warning }

// Trend compare au précédent audit : "up", "down", "same" ou "".
func (s SiteSummary) Trend() string {
	switch {
	case s.PrevFindings < 0 || s.LastID == 0:
		return ""
	case s.Findings() > s.PrevFindings:
		return "up"
	case s.Findings() < s.PrevFindings:
		return "down"
	}
	return "same"
}

// Due renvoie la date du prochain audit souhaité (zéro : pas de rappel).
func (s SiteSummary) Due() time.Time {
	if s.ReminderDays <= 0 || s.LastAudit.IsZero() {
		return time.Time{}
	}
	return s.LastAudit.AddDate(0, 0, s.ReminderDays)
}

// Overdue indique un audit en retard.
func (s SiteSummary) Overdue(now time.Time) bool { d := s.Due(); return !d.IsZero() && now.After(d) }

// WithDefaultReminder applique la fréquence par défaut si le site n'en a pas.
func (s SiteSummary) WithDefaultReminder(days int) SiteSummary {
	if !s.reminderSet {
		s.ReminderDays = days
	}
	return s
}

// ListSites liste les sites de dataDir, triés par nom.
func ListSites(dataDir string) ([]SiteSummary, error) {
	entries, err := os.ReadDir(SitesDir(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []SiteSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		s, err := OpenSite(dataDir, e.Name())
		if err != nil {
			continue
		}
		if sum, err := s.Summary(); err == nil {
			out = append(out, sum)
		}
		s.Close()
	}
	sort.Slice(out, func(a, b int) bool { return strings.ToLower(out[a].Name) < strings.ToLower(out[b].Name) })
	return out, nil
}

// Summary calcule le résumé du site pour le tableau de bord.
func (s *Site) Summary() (SiteSummary, error) {
	info, err := s.Info()
	if err != nil {
		return SiteSummary{}, err
	}
	sum := SiteSummary{SiteInfo: info, PrevFindings: -1}
	var rem sql.NullInt64
	s.db.QueryRow(`SELECT reminder_days FROM site WHERE id = 1`).Scan(&rem)
	sum.ReminderDays, sum.reminderSet = int(rem.Int64), rem.Valid
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE status = 'done'`).Scan(&sum.Audits)
	if sum.LastID, err = s.LatestAudit(); err != nil || sum.LastID == 0 {
		return sum, err
	}
	a, err := s.GetAudit(sum.LastID)
	if err != nil {
		return sum, err
	}
	sum.LastAudit, sum.Devices = a.Started, a.Devices
	counts, _ := s.FindingCountsByAudit()
	sum.Critical, sum.Warning = counts[a.ID]["critical"], counts[a.ID]["warning"]
	if prev, _ := s.PreviousAudit(a.ID); prev != 0 {
		sum.PrevFindings = counts[prev]["critical"] + counts[prev]["warning"]
	}
	return sum, nil
}

// SetReminder fixe la fréquence d'audit souhaitée du site (jours) ; une
// valeur négative revient à la valeur par défaut des préférences.
func (s *Site) SetReminder(days int) error {
	var v any
	if days >= 0 {
		v = days
	}
	_, err := s.db.Exec(`UPDATE site SET reminder_days = ? WHERE id = 1`, v)
	return err
}
