package store

import "strings"

// Comment lit le commentaire du technicien sur un audit.
func (s *Site) Comment(auditID int64) (string, error) {
	var c string
	err := s.db.QueryRow(`SELECT comment FROM audit WHERE id = ?`, auditID).Scan(&c)
	return c, err
}

// SetComment enregistre le commentaire du technicien (synthèse du rapport).
func (s *Site) SetComment(auditID int64, text string) error {
	_, err := s.db.Exec(`UPDATE audit SET comment = ? WHERE id = ?`, strings.TrimSpace(text), auditID)
	return err
}

// Recommendations renvoie les recommandations personnalisées d'un audit, par règle.
func (s *Site) Recommendations(auditID int64) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT rule, text FROM recommendation WHERE audit_id = ?`, auditID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var r, t string
		if err := rows.Scan(&r, &t); err != nil {
			return nil, err
		}
		out[r] = t
	}
	return out, rows.Err()
}

// SetRecommendation enregistre (ou efface si text est vide) la recommandation
// personnalisée d'une règle pour un audit.
func (s *Site) SetRecommendation(auditID int64, rule, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		_, err := s.db.Exec(`DELETE FROM recommendation WHERE audit_id = ? AND rule = ?`, auditID, rule)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO recommendation (audit_id, rule, text) VALUES (?, ?, ?)
		ON CONFLICT (audit_id, rule) DO UPDATE SET text = excluded.text`, auditID, rule, text)
	return err
}
