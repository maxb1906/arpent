package report

import (
	"encoding/csv"
	"encoding/json"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/maxb1906/arpent/assets"
	"github.com/maxb1906/arpent/internal/i18n"
)

// Formats d'export disponibles (« pdf » passe par un navigateur, voir PDF).
var Formats = []string{"html", "pdf", "csv", "json"}

// TemplatesDir, s'il est défini et contient report.html et/ou report.css,
// remplace les modèles embarqués (arpent-data/templates/) : un technicien
// adapte le rapport sans recompiler.
var TemplatesDir string

// templateFile lit un modèle : version personnalisée si elle existe, sinon embarquée.
func templateFile(name string) ([]byte, error) {
	if TemplatesDir != "" {
		if b, err := os.ReadFile(filepath.Join(TemplatesDir, name)); err == nil {
			return b, nil
		}
	}
	return assets.Report.ReadFile("report/" + name)
}

// ExportTemplates copie les modèles embarqués dans dir (point de départ
// d'une personnalisation) sans écraser les fichiers existants.
func ExportTemplates(dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var written []string
	for _, name := range []string{"report.html", "report.css"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		b, err := assets.Report.ReadFile("report/" + name)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return nil, err
		}
		written = append(written, path)
	}
	return written, nil
}

// HTML écrit le rapport autonome dans la langue de tr.
func HTML(w io.Writer, d *Data, tr *i18n.Translator) error {
	css, err := templateFile("report.css")
	if err != nil {
		return err
	}
	src, err := templateFile("report.html")
	if err != nil {
		return err
	}
	t, err := template.New("report.html").Funcs(i18n.TemplateFuncs(tr)).Parse(string(src))
	if err != nil {
		return err
	}
	return t.Execute(w, map[string]any{"Lang": tr.Lang(), "CSS": template.CSS(css), "D": d})
}

// CSV écrit l'inventaire : une ligne par service ouvert (et une ligne par
// appareil sans service). Séparateur « ; » pour les tableurs francophones.
func CSV(w io.Writer, d *Data, tr *i18n.Translator) error {
	io.WriteString(w, "\xef\xbb\xbf") // BOM : Excel reconnaît l'UTF-8
	cw := csv.NewWriter(w)
	if tr.Lang() == "fr" {
		cw.Comma = ';'
	}
	head := []string{"col.ip", "col.mac", "col.vendor", "col.name", "web.label", "web.location", "web.type", "web.known",
		"report.port", "report.proto", "report.service", "report.product", "report.version", "report.detail", "web.findings"}
	for i, k := range head {
		head[i] = tr.T(k)
	}
	cw.Write(head)
	for _, o := range d.Observations {
		vendor := o.Vendor
		if o.RandomMAC {
			vendor = tr.T("discover.random_mac")
		}
		typ := ""
		if o.DeviceType != "" {
			typ = tr.T("type." + o.DeviceType)
		}
		known := ""
		if o.Device.Known {
			known = tr.T("report.yes")
		}
		base := []string{o.IP, o.MAC, vendor, strings.Join(o.Names, " "), o.Device.Label, o.Device.Location, typ, known}
		fcount := map[int64]int{}
		for _, f := range d.FindingsOf(o.Device.ID) {
			fcount[f.ServiceID]++
		}
		if len(o.Services) == 0 {
			cw.Write(append(base, "", "", "", "", "", "", ""))
			continue
		}
		for _, s := range o.Services {
			detail := ""
			switch {
			case s.Details.HTTP != nil && s.Details.HTTP.Title != "":
				detail = s.Details.HTTP.Title
			case s.Details.TLS != nil:
				detail = s.Details.TLS.Subject + " " + s.Details.TLS.NotAfter.Format("2006-01-02")
			default:
				detail = strings.SplitN(s.Banner, "\n", 2)[0]
			}
			cw.Write(append(append([]string{}, base...), strconv.Itoa(s.Port), s.Proto, s.Name, s.Product, s.Version, detail, strconv.Itoa(fcount[s.ID])))
		}
	}
	cw.Flush()
	return cw.Error()
}

// jsonReport est la forme stable de l'export JSON (noms anglais).
type jsonReport struct {
	Generator string        `json:"generator"`
	Generated time.Time     `json:"generated"`
	Site      jsonSite      `json:"site"`
	Audit     jsonAudit     `json:"audit"`
	Devices   []jsonDevice  `json:"devices"`
	Findings  []jsonFinding `json:"findings"`
	Changes   []jsonChange  `json:"changes"`
}

type jsonSite struct {
	Name    string `json:"name"`
	Address string `json:"address,omitempty"`
	Contact string `json:"contact,omitempty"`
}

type jsonAudit struct {
	ID           int64     `json:"id"`
	Started      time.Time `json:"started"`
	Finished     time.Time `json:"finished"`
	Profile      string    `json:"profile"`
	Ranges       string    `json:"ranges"`
	Technician   string    `json:"technician,omitempty"`
	Mode         string    `json:"mode"`
	AuthorizedAt time.Time `json:"authorized_at,omitzero"`
	Previous     int64     `json:"previous_audit,omitempty"`
}

type jsonDevice struct {
	ID       int64         `json:"id"`
	IP       string        `json:"ip"`
	MAC      string        `json:"mac,omitempty"`
	Vendor   string        `json:"vendor,omitempty"`
	Random   bool          `json:"random_mac,omitempty"`
	Names    []string      `json:"names,omitempty"`
	Label    string        `json:"label,omitempty"`
	Location string        `json:"location,omitempty"`
	Owner    string        `json:"owner,omitempty"`
	Known    bool          `json:"known"`
	Type     string        `json:"type,omitempty"`
	Services []jsonService `json:"services"`
}

type jsonService struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Name    string `json:"name,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Details any    `json:"details,omitempty"`
}

type jsonFinding struct {
	Rule     string            `json:"rule"`
	Level    string            `json:"level"`
	Title    string            `json:"title"`
	Explain  string            `json:"explanation"`
	Fix      string            `json:"recommendation"`
	DeviceID int64             `json:"device_id"`
	IP       string            `json:"ip"`
	Port     int               `json:"port,omitempty"`
	Proto    string            `json:"proto,omitempty"`
	Params   map[string]string `json:"params,omitempty"`
}

type jsonChange struct {
	Kind     string `json:"kind"`
	Field    string `json:"field,omitempty"`
	DeviceID int64  `json:"device_id,omitempty"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
}

// JSON écrit l'audit complet ; les textes des points d'attention sont dans
// la langue de tr, les clés restent en anglais.
func JSON(w io.Writer, d *Data, tr *i18n.Translator) error {
	r := jsonReport{
		Generator: d.Generator, Generated: d.Generated.UTC(),
		Site: jsonSite{d.Site.Name, d.Site.Address, d.Site.Contact},
		Audit: jsonAudit{ID: d.Audit.ID, Started: d.Audit.Started.UTC(), Finished: d.Audit.Finished.UTC(), Profile: d.Audit.Profile,
			Ranges: d.Audit.Ranges, Technician: d.Audit.Technician, Mode: d.Audit.Mode, AuthorizedAt: d.Audit.AuthorizedAt.UTC()},
		Devices: []jsonDevice{}, Findings: []jsonFinding{}, Changes: []jsonChange{},
	}
	if d.Audit.AuthorizedAt.IsZero() {
		r.Audit.AuthorizedAt = time.Time{}
	}
	if d.Previous != nil {
		r.Audit.Previous = d.Previous.ID
	}
	for _, o := range d.Observations {
		jd := jsonDevice{ID: o.Device.ID, IP: o.IP, MAC: o.MAC, Vendor: o.Vendor, Random: o.RandomMAC, Names: o.Names,
			Label: o.Device.Label, Location: o.Device.Location, Owner: o.Device.Owner, Known: o.Device.Known, Type: o.DeviceType, Services: []jsonService{}}
		for _, s := range o.Services {
			det := s.Details
			jd.Services = append(jd.Services, jsonService{s.Port, s.Proto, s.Name, s.Product, s.Version, det})
		}
		r.Devices = append(r.Devices, jd)
	}
	for _, f := range d.Findings {
		pairs := make([]string, 0, 2*len(f.Params))
		for k, v := range f.Params {
			pairs = append(pairs, k, v)
		}
		r.Findings = append(r.Findings, jsonFinding{Rule: f.Rule, Level: f.Level,
			Title: tr.T("rule."+f.Rule+".title", pairs...), Explain: tr.T("rule."+f.Rule+".explain", pairs...), Fix: tr.T("rule."+f.Rule+".fix", pairs...),
			DeviceID: f.DeviceID, IP: f.IP, Port: f.Port, Proto: f.Proto, Params: f.Params})
	}
	for _, c := range d.Changes {
		r.Changes = append(r.Changes, jsonChange{c.Kind, c.Field, c.DeviceID, c.IP, c.Port, c.Proto, c.Before, c.After})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Write écrit le rapport au format demandé.
func Write(w io.Writer, format string, d *Data, tr *i18n.Translator) error {
	switch format {
	case "csv":
		return CSV(w, d, tr)
	case "json":
		return JSON(w, d, tr)
	default:
		return HTML(w, d, tr)
	}
}

// ContentType renvoie le type MIME d'un format.
func ContentType(format string) string {
	switch format {
	case "csv":
		return "text/csv; charset=utf-8"
	case "json":
		return "application/json"
	case "pdf":
		return "application/pdf"
	}
	return "text/html; charset=utf-8"
}

// WriteFile écrit le rapport dans path (fichier temporaire puis renommage).
func WriteFile(path, format string, d *Data, tr *i18n.Translator) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := Write(tmp, format, d, tr); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
