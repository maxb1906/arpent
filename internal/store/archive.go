package store

import (
	"archive/zip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// ArchiveExt est l'extension des archives de site.
const ArchiveExt = ".arpent"

// manifest décrit une archive .arpent.
type manifest struct {
	Format   string    `json:"format"` // « arpent-site »
	Version  int       `json:"version"`
	Name     string    `json:"name"`
	Slug     string    `json:"slug"`
	Schema   int       `json:"schema"`
	Exported time.Time `json:"exported"`
	Audits   int       `json:"audits"`
}

// Export écrit le site dans une archive .arpent (zip : manifest.json, une
// copie cohérente de site.db, les rapports).
func (s *Site) Export(w io.Writer) error {
	tmp, err := os.MkdirTemp("", "arpent-export-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	dbCopy := filepath.Join(tmp, "site.db")
	// VACUUM INTO : copie cohérente même pendant une utilisation (WAL inclus).
	if _, err := s.db.Exec(`VACUUM INTO ?`, dbCopy); err != nil {
		return err
	}
	info, err := s.Info()
	if err != nil {
		return err
	}
	var n, schema int
	s.db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&n)
	s.db.QueryRow(`PRAGMA user_version`).Scan(&schema)
	zw := zip.NewWriter(w)
	m, _ := json.MarshalIndent(manifest{"arpent-site", 1, info.Name, s.Slug, schema, time.Now().UTC(), n}, "", "  ")
	if err := addZip(zw, "manifest.json", strings.NewReader(string(m))); err != nil {
		return err
	}
	f, err := os.Open(dbCopy)
	if err != nil {
		return err
	}
	err = addZip(zw, "site.db", f)
	f.Close()
	if err != nil {
		return err
	}
	entries, _ := os.ReadDir(s.ReportsDir())
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		f, err := os.Open(filepath.Join(s.ReportsDir(), e.Name()))
		if err != nil {
			return err
		}
		err = addZip(zw, "rapports/"+e.Name(), f)
		f.Close()
		if err != nil {
			return err
		}
	}
	return zw.Close()
}

func addZip(zw *zip.Writer, name string, r io.Reader) error {
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()})
	if err != nil {
		return err
	}
	_, err = io.Copy(w, r)
	return err
}

// ImportResult décrit le résultat d'un import.
type ImportResult struct {
	Slug    string
	Name    string
	Created bool // le site n'existait pas
	Added   int  // audits ajoutés
	Skipped int  // audits déjà présents
	Reports int  // rapports copiés
}

// MaxArchiveDB limite la taille de la base dans une archive (protection).
const MaxArchiveDB = 2 << 30

// Import lit une archive .arpent dans dataDir : crée le site s'il n'existe
// pas, sinon fusionne les audits absents (identifiés par leur uid).
// L'appelant doit ensuite recalculer les changements (diff) du site.
func Import(dataDir string, r io.ReaderAt, size int64) (*ImportResult, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("archive illisible : %w", err)
	}
	var m manifest
	var dbFile *zip.File
	var reports []*zip.File
	for _, f := range zr.File {
		switch {
		case f.Name == "manifest.json":
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			err = json.NewDecoder(io.LimitReader(rc, 1<<20)).Decode(&m)
			rc.Close()
			if err != nil {
				return nil, err
			}
		case f.Name == "site.db":
			dbFile = f
		case strings.HasPrefix(f.Name, "rapports/"):
			// Protection « zip slip » : un simple nom de fichier, sans dossier.
			base := path.Base(f.Name)
			if base == f.Name[len("rapports/"):] && base != "." && base != ".." && !strings.ContainsAny(base, `\/:`) && !strings.HasPrefix(base, ".") {
				reports = append(reports, f)
			}
		}
	}
	if m.Format != "arpent-site" || dbFile == nil {
		return nil, errors.New("ce fichier n'est pas une archive de site Arpent")
	}
	if dbFile.UncompressedSize64 > MaxArchiveDB {
		return nil, errors.New("base trop volumineuse")
	}
	tmp, err := os.MkdirTemp("", "arpent-import-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	srcDir := filepath.Join(tmp, "site")
	os.MkdirAll(srcDir, 0o755)
	if err := extract(dbFile, filepath.Join(srcDir, "site.db")); err != nil {
		return nil, err
	}
	// Ouvrir la copie la migre au schéma courant et vérifie qu'elle est saine.
	srcDB, err := open(srcDir)
	if err != nil {
		return nil, fmt.Errorf("base de l'archive : %w", err)
	}
	var name, slug string
	err = srcDB.QueryRow(`SELECT name, slug FROM site WHERE id = 1`).Scan(&name, &slug)
	srcDB.Close()
	if err != nil {
		return nil, err
	}
	slug = Slugify(slug)
	if slug == "" {
		slug = Slugify(name)
	}
	res := &ImportResult{Slug: slug, Name: name}
	dst, err := OpenSite(dataDir, slug)
	if errors.Is(err, ErrNoSite) {
		res.Created = true
		dst, err = CreateSite(dataDir, name)
		if err == nil && dst.Slug != slug {
			res.Slug = dst.Slug
		}
	}
	if err != nil {
		return nil, err
	}
	defer dst.Close()
	res.Added, res.Skipped, err = dst.merge(filepath.Join(srcDir, "site.db"))
	if err != nil {
		return nil, err
	}
	for _, f := range reports {
		target := filepath.Join(dst.ReportsDir(), path.Base(f.Name))
		if _, err := os.Stat(target); err == nil {
			continue
		}
		if err := extract(f, target); err != nil {
			return nil, err
		}
		res.Reports++
	}
	return res, nil
}

func extract(f *zip.File, dst string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, io.LimitReader(rc, MaxArchiveDB))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// merge ajoute à la base les audits de srcPath qu'elle ne contient pas.
func (s *Site) merge(srcPath string) (added, skipped int, err error) {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `ATTACH DATABASE ? AS src`, srcPath); err != nil {
		return 0, 0, err
	}
	defer conn.ExecContext(ctx, `DETACH DATABASE src`)
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	exec := func(q string, args ...any) error {
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	}
	// Fiche du site : compléter les champs vides.
	if err := exec(`UPDATE main.site SET
		address = CASE WHEN address = '' THEN (SELECT address FROM src.site) ELSE address END,
		contact = CASE WHEN contact = '' THEN (SELECT contact FROM src.site) ELSE contact END,
		notes   = CASE WHEN notes = ''   THEN (SELECT notes FROM src.site)   ELSE notes END`); err != nil {
		return 0, 0, err
	}
	// Appareils : nouveaux, puis annotations manquantes et statut « connu ».
	if err := exec(`INSERT INTO main.device (identity, mac, label, location, owner, notes, known, known_at)
		SELECT identity, mac, label, location, owner, notes, known, known_at FROM src.device
		WHERE identity NOT IN (SELECT identity FROM main.device)`); err != nil {
		return 0, 0, err
	}
	if err := exec(`UPDATE main.device SET
		label    = CASE WHEN label = ''    THEN COALESCE((SELECT d.label    FROM src.device d WHERE d.identity = main.device.identity), '') ELSE label END,
		location = CASE WHEN location = '' THEN COALESCE((SELECT d.location FROM src.device d WHERE d.identity = main.device.identity), '') ELSE location END,
		owner    = CASE WHEN owner = ''    THEN COALESCE((SELECT d.owner    FROM src.device d WHERE d.identity = main.device.identity), '') ELSE owner END,
		notes    = CASE WHEN notes = ''    THEN COALESCE((SELECT d.notes    FROM src.device d WHERE d.identity = main.device.identity), '') ELSE notes END,
		known_at = CASE WHEN known = 0 THEN (SELECT d.known_at FROM src.device d WHERE d.identity = main.device.identity AND d.known = 1) ELSE known_at END,
		known    = MAX(known, COALESCE((SELECT d.known FROM src.device d WHERE d.identity = main.device.identity), 0))`); err != nil {
		return 0, 0, err
	}
	// Audits absents (par uid) : copie avec nouvel identifiant.
	if err := exec(`CREATE TEMP TABLE IF NOT EXISTS amap (src_id INTEGER PRIMARY KEY, dst_id INTEGER)`); err != nil {
		return 0, 0, err
	}
	exec(`DELETE FROM temp.amap`)
	rows, err := tx.QueryContext(ctx, `SELECT id, uid FROM src.audit ORDER BY started_at, id`)
	if err != nil {
		return 0, 0, err
	}
	type au struct {
		id  int64
		uid sql.NullString
	}
	var list []au
	for rows.Next() {
		var a au
		if err := rows.Scan(&a.id, &a.uid); err != nil {
			rows.Close()
			return 0, 0, err
		}
		list = append(list, a)
	}
	rows.Close()
	for _, a := range list {
		var n int
		tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM main.audit WHERE uid = ?`, a.uid.String).Scan(&n)
		if n > 0 {
			skipped++
			continue
		}
		r, err := tx.ExecContext(ctx, `INSERT INTO main.audit (started_at, finished_at, status, technician, ranges, profile, mode, targets,
			authorized_at, authorized_by, error, comment, uid)
			SELECT started_at, finished_at, status, technician, ranges, profile, mode, targets, authorized_at, authorized_by, error, comment,
			COALESCE(uid, lower(hex(randomblob(16)))) FROM src.audit WHERE id = ?`, a.id)
		if err != nil {
			return 0, 0, err
		}
		dstID, _ := r.LastInsertId()
		if err := exec(`INSERT INTO temp.amap (src_id, dst_id) VALUES (?, ?)`, a.id, dstID); err != nil {
			return 0, 0, err
		}
		added++
	}
	steps := []string{
		`INSERT INTO main.observation (audit_id, device_id, ip, mac, vendor, random_mac, names, methods, device_type, rtt_us, extra)
		 SELECT am.dst_id, md.id, o.ip, o.mac, o.vendor, o.random_mac, o.names, o.methods, o.device_type, o.rtt_us, o.extra
		 FROM src.observation o JOIN temp.amap am ON am.src_id = o.audit_id
		 JOIN src.device sd ON sd.id = o.device_id JOIN main.device md ON md.identity = sd.identity`,
		`INSERT INTO main.service (observation_id, port, proto, state, name, product, version, banner, details, raw)
		 SELECT mo.id, sv.port, sv.proto, sv.state, sv.name, sv.product, sv.version, sv.banner, sv.details, sv.raw
		 FROM src.service sv JOIN src.observation so ON so.id = sv.observation_id
		 JOIN temp.amap am ON am.src_id = so.audit_id
		 JOIN src.device sd ON sd.id = so.device_id JOIN main.device md ON md.identity = sd.identity
		 JOIN main.observation mo ON mo.audit_id = am.dst_id AND mo.device_id = md.id`,
		`INSERT INTO main.finding (audit_id, device_id, service_id, rule, level, params)
		 SELECT am.dst_id, md.id,
		   (SELECT msv.id FROM main.service msv JOIN main.observation mo ON mo.id = msv.observation_id
		    JOIN src.service ssv ON ssv.id = f.service_id
		    WHERE mo.audit_id = am.dst_id AND mo.device_id = md.id AND msv.port = ssv.port AND msv.proto = ssv.proto),
		   f.rule, f.level, f.params
		 FROM src.finding f JOIN temp.amap am ON am.src_id = f.audit_id
		 JOIN src.device sd ON sd.id = f.device_id JOIN main.device md ON md.identity = sd.identity`,
		`INSERT INTO main.recommendation (audit_id, rule, text)
		 SELECT am.dst_id, r.rule, r.text FROM src.recommendation r JOIN temp.amap am ON am.src_id = r.audit_id`,
		`UPDATE main.device SET
		   first_audit = (SELECT o.audit_id FROM main.observation o JOIN main.audit a ON a.id = o.audit_id
		                  WHERE o.device_id = main.device.id ORDER BY a.started_at, a.id LIMIT 1),
		   last_audit  = (SELECT o.audit_id FROM main.observation o JOIN main.audit a ON a.id = o.audit_id
		                  WHERE o.device_id = main.device.id ORDER BY a.started_at DESC, a.id DESC LIMIT 1)`,
	}
	for _, q := range steps {
		if err := exec(q); err != nil {
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return added, skipped, nil
}

// DoneAuditsChrono renvoie les audits terminés, du plus ancien au plus récent.
func (s *Site) DoneAuditsChrono() ([]int64, error) {
	rows, err := s.db.Query(`SELECT id FROM audit WHERE status = 'done' ORDER BY started_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
