package store

import "strings"

// Types de changements entre deux audits (§ 5.6).
const (
	ChangeNewDevice      = "new_device"
	ChangeGoneDevice     = "gone_device"
	ChangePortOpened     = "port_opened"
	ChangePortClosed     = "port_closed"
	ChangeServiceChanged = "service_changed"
	ChangeIPChanged      = "ip_changed"    // même appareil (MAC), nouvelle IP
	ChangeIPReassigned   = "ip_reassigned" // même IP, autre appareil
)

// Change est une différence entre un audit et le précédent.
type Change struct {
	ID        int64
	AuditID   int64
	PrevAudit int64
	Kind      string
	DeviceID  int64
	Port      int
	Proto     string
	Field     string // pour service_changed : product, cert, ssh, name…
	Before    string
	After     string
	// Champs joints pour l'affichage.
	IP    string
	Label string
	Known bool
}

// SaveChanges remplace les changements enregistrés pour un audit.
func (s *Site) SaveChanges(auditID, prevID int64, cs []Change) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM change WHERE audit_id = ?`, auditID); err != nil {
		return err
	}
	for _, c := range cs {
		var port, proto, dev any
		if c.Port != 0 {
			port, proto = c.Port, c.Proto
		}
		if c.DeviceID != 0 {
			dev = c.DeviceID
		}
		before := c.Before
		if c.Field != "" {
			before = c.Field + "\x1f" + c.Before
		}
		if _, err := tx.Exec(`INSERT INTO change (audit_id, prev_audit, kind, device_id, port, proto, before, after) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			auditID, prevID, c.Kind, dev, port, proto, before, c.After); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Changes lit les changements enregistrés pour un audit.
func (s *Site) Changes(auditID int64) ([]Change, error) {
	rows, err := s.db.Query(`SELECT c.id, c.audit_id, COALESCE(c.prev_audit, 0), c.kind, COALESCE(c.device_id, 0),
		COALESCE(c.port, 0), COALESCE(c.proto, ''), c.before, c.after, COALESCE(d.label, ''), COALESCE(d.known, 0),
		COALESCE((SELECT o.ip FROM observation o WHERE o.device_id = c.device_id ORDER BY (o.audit_id = c.audit_id) DESC, o.audit_id DESC LIMIT 1), '')
		FROM change c LEFT JOIN device d ON d.id = c.device_id WHERE c.audit_id = ? ORDER BY c.id`, auditID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Change
	for rows.Next() {
		var c Change
		if err := rows.Scan(&c.ID, &c.AuditID, &c.PrevAudit, &c.Kind, &c.DeviceID, &c.Port, &c.Proto, &c.Before, &c.After, &c.Label, &c.Known, &c.IP); err != nil {
			return nil, err
		}
		if f, b, ok := strings.Cut(c.Before, "\x1f"); ok {
			c.Field, c.Before = f, b
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
