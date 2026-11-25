package store

import (
	"encoding/json"
	"sort"
)

// Finding est un point d'attention d'un audit.
type Finding struct {
	ID        int64
	AuditID   int64
	DeviceID  int64
	ServiceID int64 // 0 : concerne l'appareil entier
	Rule      string
	Level     string // info, warning, critical
	Params    map[string]string
	// Champs joints pour l'affichage.
	IP    string
	Label string
	Port  int
	Proto string
}

// SaveFindings remplace les points d'attention d'un audit.
func (s *Site) SaveFindings(auditID int64, fs []Finding) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM finding WHERE audit_id = ?`, auditID); err != nil {
		return err
	}
	for _, f := range fs {
		params, _ := json.Marshal(f.Params)
		var svc any
		if f.ServiceID != 0 {
			svc = f.ServiceID
		}
		if _, err := tx.Exec(`INSERT INTO finding (audit_id, device_id, service_id, rule, level, params) VALUES (?, ?, ?, ?, ?, ?)`,
			auditID, f.DeviceID, svc, f.Rule, f.Level, string(params)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func levelRank(l string) int {
	switch l {
	case "critical":
		return 0
	case "warning":
		return 1
	}
	return 2
}

// Findings lit les points d'attention d'un audit, du plus grave au moins grave.
func (s *Site) Findings(auditID int64) ([]Finding, error) {
	rows, err := s.db.Query(`SELECT f.id, f.audit_id, f.device_id, COALESCE(f.service_id, 0), f.rule, f.level, f.params,
		o.ip, d.label, COALESCE(sv.port, 0), COALESCE(sv.proto, '')
		FROM finding f
		JOIN device d ON d.id = f.device_id
		JOIN observation o ON o.device_id = f.device_id AND o.audit_id = f.audit_id
		LEFT JOIN service sv ON sv.id = f.service_id
		WHERE f.audit_id = ?`, auditID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		var params string
		if err := rows.Scan(&f.ID, &f.AuditID, &f.DeviceID, &f.ServiceID, &f.Rule, &f.Level, &params, &f.IP, &f.Label, &f.Port, &f.Proto); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(params), &f.Params)
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if levelRank(a.Level) != levelRank(b.Level) {
			return levelRank(a.Level) < levelRank(b.Level)
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if a.IP != b.IP {
			return ipLess(a.IP, b.IP)
		}
		return a.Port < b.Port
	})
	return out, rows.Err()
}

// FindingCounts compte les points d'attention par niveau.
func FindingCounts(fs []Finding) map[string]int {
	m := map[string]int{"critical": 0, "warning": 0, "info": 0}
	for _, f := range fs {
		m[f.Level]++
	}
	return m
}

// FindingCountsByAudit compte les points d'attention par audit et par niveau.
func (s *Site) FindingCountsByAudit() (map[int64]map[string]int, error) {
	rows, err := s.db.Query(`SELECT audit_id, level, COUNT(*) FROM finding GROUP BY audit_id, level`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]map[string]int{}
	for rows.Next() {
		var id int64
		var level string
		var n int
		if err := rows.Scan(&id, &level, &n); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[string]int{}
		}
		out[id][level] = n
	}
	return out, rows.Err()
}
