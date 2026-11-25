package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/maxb1906/arpent/internal/audit"
	"github.com/maxb1906/arpent/internal/probe"
)

// Statuts d'un audit.
const (
	StatusRunning   = "running"
	StatusDone      = "done"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// AuditMeta décrit un audit au moment de son lancement.
type AuditMeta struct {
	Technician   string
	Ranges       string
	Profile      string
	Mode         string
	Targets      int
	AuthorizedAt time.Time // zéro : pas de confirmation
	AuthorizedBy string
}

// Audit est une ligne de la table audit.
type Audit struct {
	ID       int64
	Started  time.Time
	Finished time.Time
	Status   string
	AuditMeta
	Error   string
	Devices int // appareils observés
	Ports   int // ports ouverts
}

func ts(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(TimeFormat)
}

func parseTS(s sql.NullString) time.Time {
	if !s.Valid {
		return time.Time{}
	}
	t, _ := time.Parse(TimeFormat, s.String)
	return t
}

// BeginAudit enregistre un audit « en cours » et renvoie son identifiant.
func (s *Site) BeginAudit(m AuditMeta) (int64, error) {
	if m.Mode == "" {
		m.Mode = "standard"
	}
	r, err := s.db.Exec(`INSERT INTO audit (started_at, status, technician, ranges, profile, mode, targets, authorized_at, authorized_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts(time.Now()), StatusRunning, m.Technician, m.Ranges, m.Profile, m.Mode, m.Targets, ts(m.AuthorizedAt), m.AuthorizedBy)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

// EndAudit marque un audit comme échoué ou annulé.
func (s *Site) EndAudit(id int64, status string, cause error) error {
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}
	_, err := s.db.Exec(`UPDATE audit SET status = ?, finished_at = ?, error = ? WHERE id = ?`, status, ts(time.Now()), msg, id)
	return err
}

// Authorized indique si une confirmation d'autorisation a déjà été donnée
// pour ce site, et quand.
func (s *Site) Authorized() (time.Time, bool) {
	var v sql.NullString
	s.db.QueryRow(`SELECT MIN(authorized_at) FROM audit WHERE authorized_at IS NOT NULL`).Scan(&v)
	t := parseTS(v)
	return t, !t.IsZero()
}

// Identity calcule l'identité stable d'un appareil : la MAC si elle est
// connue, sinon l'IP et le premier nom.
func Identity(mac net.HardwareAddr, ip string, names []string) string {
	if len(mac) > 0 {
		return "mac:" + strings.ToLower(mac.String())
	}
	id := "ip:" + ip
	if len(names) > 0 {
		id += "|" + strings.ToLower(names[0])
	}
	return id
}

// CompleteAudit enregistre le résultat d'un audit commencé par BeginAudit.
// deviceType donne le type deviné d'un hôte (peut être nil).
func (s *Site) CompleteAudit(id int64, res *audit.Result, deviceType func(audit.Host) string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, h := range res.Hosts {
		ident := Identity(h.MAC, h.IP.String(), h.Names)
		mac := ""
		if h.MAC != nil {
			mac = strings.ToLower(h.MAC.String())
		}
		var devID int64
		err := tx.QueryRow(`INSERT INTO device (identity, mac, first_audit, last_audit) VALUES (?, ?, ?, ?)
			ON CONFLICT (identity) DO UPDATE SET last_audit = excluded.last_audit
			RETURNING id`, ident, mac, id, id).Scan(&devID)
		if err != nil {
			return err
		}
		names, _ := json.Marshal(nonNil(h.Names))
		methods, _ := json.Marshal(nonNil(h.Methods))
		dt := ""
		if deviceType != nil {
			dt = deviceType(h)
		}
		r, err := tx.Exec(`INSERT INTO observation (audit_id, device_id, ip, mac, vendor, random_mac, names, methods, device_type, rtt_us)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, devID, h.IP.String(), mac, h.Vendor, h.Random, string(names), string(methods), dt, h.RTT.Microseconds())
		if err != nil {
			return err
		}
		obsID, _ := r.LastInsertId()
		for _, p := range h.Ports {
			details, _ := json.Marshal(p.Service)
			if _, err := tx.Exec(`INSERT INTO service (observation_id, port, proto, name, product, version, banner, details, raw)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				obsID, p.Port, p.Proto, p.Service.Name, p.Service.Product, p.Service.Version, p.Service.Banner, string(details), p.Response); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`UPDATE audit SET status = ?, finished_at = ? WHERE id = ?`, StatusDone, ts(res.Finished), id); err != nil {
		return err
	}
	return tx.Commit()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

const auditCols = `a.id, a.started_at, a.finished_at, a.status, a.technician, a.ranges, a.profile, a.mode, a.targets,
	a.authorized_at, a.authorized_by, a.error,
	(SELECT COUNT(*) FROM observation o WHERE o.audit_id = a.id),
	(SELECT COUNT(*) FROM service sv JOIN observation o ON o.id = sv.observation_id WHERE o.audit_id = a.id)`

func scanAudit(sc interface{ Scan(...any) error }) (Audit, error) {
	var a Audit
	var started, finished, auth sql.NullString
	err := sc.Scan(&a.ID, &started, &finished, &a.Status, &a.Technician, &a.Ranges, &a.Profile, &a.Mode, &a.Targets,
		&auth, &a.AuthorizedBy, &a.Error, &a.Devices, &a.Ports)
	a.Started, a.Finished, a.AuthorizedAt = parseTS(started), parseTS(finished), parseTS(auth)
	return a, err
}

// Audits liste les audits du site, du plus récent au plus ancien.
func (s *Site) Audits() ([]Audit, error) {
	rows, err := s.db.Query(`SELECT ` + auditCols + ` FROM audit a ORDER BY a.started_at DESC, a.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Audit
	for rows.Next() {
		a, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAudit lit un audit.
func (s *Site) GetAudit(id int64) (Audit, error) {
	return scanAudit(s.db.QueryRow(`SELECT `+auditCols+` FROM audit a WHERE a.id = ?`, id))
}

// LatestAudit renvoie le dernier audit terminé (0 s'il n'y en a pas).
func (s *Site) LatestAudit() (int64, error) {
	var id sql.NullInt64
	err := s.db.QueryRow(`SELECT id FROM audit WHERE status = 'done' ORDER BY started_at DESC, id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id.Int64, err
}

// PreviousAudit renvoie l'audit terminé qui précède id (0 s'il n'y en a pas).
func (s *Site) PreviousAudit(id int64) (int64, error) {
	var prev sql.NullInt64
	err := s.db.QueryRow(`SELECT id FROM audit WHERE status = 'done' AND id < ? ORDER BY id DESC LIMIT 1`, id).Scan(&prev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return prev.Int64, err
}

// Device est un appareil et ses annotations.
type Device struct {
	ID         int64
	Identity   string
	MAC        string
	Label      string
	Location   string
	Owner      string
	Notes      string
	Known      bool
	KnownAt    time.Time
	FirstAudit int64
	LastAudit  int64
}

// Service est un port ouvert observé.
type Service struct {
	ID      int64
	Port    int
	Proto   string
	Name    string
	Product string
	Version string
	Banner  string
	Details probe.Service
	Raw     []byte
}

// Key identifie un service sur un appareil (« 443/tcp »).
func (s Service) Key() string { return strconv.Itoa(s.Port) + "/" + s.Proto }

// Observation est un appareil vu lors d'un audit.
type Observation struct {
	ID         int64
	AuditID    int64
	Device     Device
	IP         string
	MAC        string
	Vendor     string
	RandomMAC  bool
	Names      []string
	Methods    []string
	DeviceType string
	RTT        time.Duration
	Services   []Service
}

// DisplayName : nom convivial, sinon premier nom réseau, sinon IP.
func (o Observation) DisplayName() string {
	if o.Device.Label != "" {
		return o.Device.Label
	}
	if len(o.Names) > 0 {
		return o.Names[0]
	}
	return o.IP
}

const deviceCols = `d.id, d.identity, d.mac, d.label, d.location, d.owner, d.notes, d.known, d.known_at, d.first_audit, d.last_audit`

func scanDevice(dst *Device, extra ...any) []any {
	return append([]any{&dst.ID, &dst.Identity, &dst.MAC, &dst.Label, &dst.Location, &dst.Owner, &dst.Notes, &dst.Known}, extra...)
}

// Observations charge les appareils et services d'un audit, triés par IP.
func (s *Site) Observations(auditID int64) ([]Observation, error) {
	return s.observations(`o.audit_id = ?`, auditID)
}

// DeviceHistory renvoie toutes les observations d'un appareil, de la plus
// ancienne à la plus récente.
func (s *Site) DeviceHistory(deviceID int64) ([]Observation, error) {
	return s.observations(`o.device_id = ?`, deviceID)
}

func (s *Site) observations(where string, arg any) ([]Observation, error) {
	rows, err := s.db.Query(`SELECT o.id, o.audit_id, o.ip, o.mac, o.vendor, o.random_mac, o.names, o.methods, o.device_type, o.rtt_us, `+
		deviceCols+` FROM observation o JOIN device d ON d.id = o.device_id WHERE `+where+` ORDER BY o.audit_id, o.id`, arg)
	if err != nil {
		return nil, err
	}
	var out []Observation
	byID := map[int64]int{}
	for rows.Next() {
		var o Observation
		var names, methods string
		var rtt int64
		var knownAt sql.NullString
		var first, last sql.NullInt64
		dst := []any{&o.ID, &o.AuditID, &o.IP, &o.MAC, &o.Vendor, &o.RandomMAC, &names, &methods, &o.DeviceType, &rtt}
		dst = append(dst, scanDevice(&o.Device, &knownAt, &first, &last)...)
		if err := rows.Scan(dst...); err != nil {
			rows.Close()
			return nil, err
		}
		o.Device.KnownAt, o.Device.FirstAudit, o.Device.LastAudit = parseTS(knownAt), first.Int64, last.Int64
		json.Unmarshal([]byte(names), &o.Names)
		json.Unmarshal([]byte(methods), &o.Methods)
		o.RTT = time.Duration(rtt) * time.Microsecond
		byID[o.ID] = len(out)
		out = append(out, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}

	srows, err := s.db.Query(`SELECT sv.observation_id, sv.id, sv.port, sv.proto, sv.name, sv.product, sv.version, sv.banner, sv.details, sv.raw
		FROM service sv JOIN observation o ON o.id = sv.observation_id WHERE `+where+` ORDER BY sv.proto, sv.port`, arg)
	if err != nil {
		return nil, err
	}
	defer srows.Close()
	for srows.Next() {
		var obs int64
		var sv Service
		var details string
		if err := srows.Scan(&obs, &sv.ID, &sv.Port, &sv.Proto, &sv.Name, &sv.Product, &sv.Version, &sv.Banner, &details, &sv.Raw); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(details), &sv.Details)
		if i, ok := byID[obs]; ok {
			out[i].Services = append(out[i].Services, sv)
		}
	}
	if where == `o.audit_id = ?` {
		sortByIP(out)
	}
	return out, srows.Err()
}

// GetDevice lit un appareil.
func (s *Site) GetDevice(id int64) (Device, error) {
	var d Device
	var knownAt sql.NullString
	var first, last sql.NullInt64
	err := s.db.QueryRow(`SELECT `+deviceCols+` FROM device d WHERE d.id = ?`, id).Scan(scanDevice(&d, &knownAt, &first, &last)...)
	d.KnownAt, d.FirstAudit, d.LastAudit = parseTS(knownAt), first.Int64, last.Int64
	return d, err
}

// Annotate met à jour les annotations d'un appareil.
func (s *Site) Annotate(id int64, label, location, owner, notes string) error {
	_, err := s.db.Exec(`UPDATE device SET label = ?, location = ?, owner = ?, notes = ? WHERE id = ?`,
		strings.TrimSpace(label), strings.TrimSpace(location), strings.TrimSpace(owner), strings.TrimSpace(notes), id)
	return err
}

// SetKnown marque (ou démarque) un appareil comme connu / validé.
func (s *Site) SetKnown(id int64, known bool) error {
	var at any
	if known {
		at = ts(time.Now())
	}
	_, err := s.db.Exec(`UPDATE device SET known = ?, known_at = ? WHERE id = ?`, known, at, id)
	return err
}

func sortByIP(obs []Observation) {
	sort.SliceStable(obs, func(a, b int) bool { return ipLess(obs[a].IP, obs[b].IP) })
}

func ipLess(a, b string) bool {
	pa, pb := net.ParseIP(a).To16(), net.ParseIP(b).To16()
	if pa == nil || pb == nil {
		return a < b
	}
	return string(pa) < string(pb)
}
