package store

import (
	"strings"
	"unicode"
)

// Hit est un résultat de recherche transverse.
type Hit struct {
	Site     SiteInfo
	AuditID  int64
	DeviceID int64
	IP       string
	Name     string
	Field    string // ip, mac, name, vendor, label, service, product, banner, finding…
	Value    string
	Port     int
	Proto    string
}

// simplify simplifie pour comparer : minuscules, sans espaces ni ponctuation
// (« SMB v1 » trouve « SMBv1 », « 00-11-22 » trouve « 00:11:22 »).
func simplify(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Search cherche q dans le dernier audit de chaque site de dataDir : IP, MAC,
// noms, fabricant, annotations, services, produits et versions, bannières,
// certificats, SMBv1, identifiants de règles. 500 résultats au plus.
func Search(dataDir, q string) ([]Hit, error) {
	nq := simplify(q)
	if len(nq) < 2 {
		return nil, nil
	}
	sites, err := ListSites(dataDir)
	if err != nil {
		return nil, err
	}
	var out []Hit
	for _, sum := range sites {
		if sum.LastID == 0 {
			continue
		}
		s, err := OpenSite(dataDir, sum.Slug)
		if err != nil {
			continue
		}
		obs, _ := s.Observations(sum.LastID)
		fs, _ := s.Findings(sum.LastID)
		s.Close()
		add := func(o Observation, field, value string, port int, proto string) bool {
			if value == "" || !strings.Contains(simplify(value), nq) {
				return false
			}
			out = append(out, Hit{Site: sum.SiteInfo, AuditID: sum.LastID, DeviceID: o.Device.ID, IP: o.IP, Name: o.DisplayName(),
				Field: field, Value: value, Port: port, Proto: proto})
			return true
		}
		for _, o := range obs {
			fields := [][2]string{{"ip", o.IP}, {"mac", o.MAC}, {"vendor", o.Vendor}, {"label", o.Device.Label},
				{"location", o.Device.Location}, {"owner", o.Device.Owner}, {"name", strings.Join(o.Names, " ")},
				{"type", o.DeviceType}, {"product", o.Extra.Product}}
			for _, f := range fields {
				if add(o, f[0], f[1], 0, "") {
					break // une ligne par appareil pour ses champs généraux
				}
			}
			for _, sv := range o.Services {
				d := sv.Details
				vals := [][2]string{{"service", sv.Name}, {"product", strings.TrimSpace(sv.Product + " " + sv.Version)}}
				if d.HTTP != nil {
					vals = append(vals, [2]string{"http", strings.TrimSpace(d.HTTP.Title + " " + d.HTTP.Server + " " + d.HTTP.PoweredBy)})
				}
				if d.TLS != nil {
					vals = append(vals, [2]string{"tls", d.TLS.Version + " " + d.TLS.Subject + " " + d.TLS.Issuer})
				}
				if d.SMB != nil {
					v := "SMB " + strings.Join(d.SMB.Dialects, " ")
					if d.SMB.SMBv1 {
						v += " SMBv1"
					}
					vals = append(vals, [2]string{"smb", v})
				}
				if d.SSH != nil {
					vals = append(vals, [2]string{"ssh", d.SSH.Software})
				}
				vals = append(vals, [2]string{"banner", strings.SplitN(sv.Banner, "\n", 2)[0]})
				for _, v := range vals {
					if add(o, v[0], v[1], sv.Port, sv.Proto) {
						break // une ligne par service
					}
				}
			}
		}
		byDev := map[int64]Observation{}
		for _, o := range obs {
			byDev[o.Device.ID] = o
		}
		for _, f := range fs {
			add(byDev[f.DeviceID], "finding", f.Rule, f.Port, f.Proto)
		}
		if len(out) >= 500 {
			return out[:500], nil
		}
	}
	return out, nil
}
