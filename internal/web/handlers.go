package web

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/maxb1906/arpent/assets"
	"github.com/maxb1906/arpent/internal/audit"
	"github.com/maxb1906/arpent/internal/config"
	"github.com/maxb1906/arpent/internal/engine"
	"github.com/maxb1906/arpent/internal/i18n"
	"github.com/maxb1906/arpent/internal/netinfo"
	"github.com/maxb1906/arpent/internal/portscan"
	"github.com/maxb1906/arpent/internal/report"
	"github.com/maxb1906/arpent/internal/store"
)

func (s *Server) routes() {
	m := http.NewServeMux()
	static, _ := fs.Sub(assets.Web, "web/static")
	m.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	m.HandleFunc("GET /login", s.login)
	m.HandleFunc("POST /lang", s.setLang)
	m.HandleFunc("POST /quit", s.quit)
	m.HandleFunc("GET /{$}", s.home)
	m.HandleFunc("GET /settings", s.settings)
	m.HandleFunc("POST /settings", s.saveSettings)
	m.HandleFunc("POST /sites", s.createSite)
	m.HandleFunc("GET /sites/{slug}", s.site)
	m.HandleFunc("POST /sites/{slug}/info", s.siteInfo)
	m.HandleFunc("POST /sites/{slug}/audits", s.startAudit)
	m.HandleFunc("GET /sites/{slug}/audits/{id}", s.auditPage)
	m.HandleFunc("POST /sites/{slug}/audits/{id}/cancel", s.cancelAudit)
	m.HandleFunc("GET /api/sites/{slug}/audits/{id}/progress", s.progress)
	m.HandleFunc("GET /sites/{slug}/audits/{id}/report", s.reportView)
	m.HandleFunc("POST /sites/{slug}/audits/{id}/report", s.reportSave)
	m.HandleFunc("GET /sites/{slug}/devices/{id}", s.devicePage)
	m.HandleFunc("POST /sites/{slug}/devices/{id}", s.annotate)
	m.HandleFunc("POST /sites/{slug}/devices/{id}/known", s.setKnown)
	s.mux = m
}

func (s *Server) openSite(r *http.Request) (*store.Site, error) {
	return store.OpenSite(s.opt.DataDir, r.PathValue("slug"))
}

func pathID(r *http.Request, name string) (int64, error) {
	return strconv.ParseInt(r.PathValue(name), 10, 64)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	sites, err := store.ListSites(s.opt.DataDir)
	if err != nil {
		s.fail(w, r, 500, err)
		return
	}
	s.render(w, r, "home", map[string]any{"Sites": sites, "DataDir": s.opt.DataDir})
}

func (s *Server) createSite(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if store.Slugify(name) == "" {
		s.fail(w, r, 400, errors.New(s.opt.Bundle.Translator(s.lang(r)).T("web.site_name_invalid")))
		return
	}
	site, err := store.CreateSite(s.opt.DataDir, name)
	if err != nil {
		s.fail(w, r, 500, err)
		return
	}
	slug := site.Slug
	site.Close()
	http.Redirect(w, r, "/sites/"+slug, http.StatusSeeOther)
}

type subnetChoice struct {
	Prefix, Interface, Address string
	Reduced                    bool
}

func (s *Server) site(w http.ResponseWriter, r *http.Request) {
	site, err := s.openSite(r)
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	defer site.Close()
	info, _ := site.Info()
	audits, err := site.Audits()
	if err != nil {
		s.fail(w, r, 500, err)
		return
	}
	authAt, authorized := site.Authorized()
	var subnets []subnetChoice
	var ranges []string
	if ifs, err := netinfo.Interfaces(); err == nil {
		for _, sn := range netinfo.SuggestSubnets(ifs) {
			subnets = append(subnets, subnetChoice{sn.Prefix.String(), sn.Interface, sn.Address.String(), sn.Reduced})
			ranges = append(ranges, sn.Prefix.String())
		}
	}
	if len(audits) > 0 && audits[0].Ranges != "" {
		ranges = []string{audits[0].Ranges} // reprendre les plages du dernier audit
	}
	cfg, _ := config.Load(s.opt.DataDir)
	technician := cfg.Technician
	for _, a := range audits {
		if technician != "" {
			break
		}
		if a.Technician != "" {
			technician = a.Technician
			break
		}
	}
	s.render(w, r, "site", map[string]any{
		"Site": info, "Audits": audits, "Authorized": authorized, "AuthorizedAt": authAt,
		"Subnets": subnets, "Ranges": strings.Join(ranges, ", "), "Profiles": portscan.Profiles, "DefaultProfile": cfg.DefaultProfile,
		"Technician": technician, "Error": r.URL.Query().Get("error"),
	})
}

func (s *Server) siteInfo(w http.ResponseWriter, r *http.Request) {
	site, err := s.openSite(r)
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	defer site.Close()
	if err := site.UpdateInfo(r.FormValue("address"), r.FormValue("contact"), r.FormValue("notes")); err != nil {
		s.fail(w, r, 500, err)
		return
	}
	http.Redirect(w, r, "/sites/"+site.Slug, http.StatusSeeOther)
}

func (s *Server) startAudit(w http.ResponseWriter, r *http.Request) {
	back := func(msgKey string) {
		http.Redirect(w, r, "/sites/"+store.Slugify(r.PathValue("slug"))+"?error="+msgKey, http.StatusSeeOther)
	}
	if s.jobs.running() != nil {
		back("web.audit_busy")
		return
	}
	site, err := s.openSite(r)
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	ranges := strings.TrimSpace(r.FormValue("ranges"))
	targets, err := netinfo.ParseRanges(ranges)
	if err != nil || len(targets) == 0 {
		site.Close()
		back("web.ranges_invalid")
		return
	}
	profile, err := portscan.ParseProfile(r.FormValue("profile"))
	if err != nil {
		site.Close()
		back("web.profile_invalid")
		return
	}
	if profile == portscan.Full && r.FormValue("confirm_full") != "1" {
		site.Close()
		back("web.full_unconfirmed")
		return
	}
	technician := strings.TrimSpace(r.FormValue("technician"))
	meta := store.AuditMeta{Technician: technician, Ranges: ranges, Profile: string(profile), Targets: len(targets)}
	if _, ok := site.Authorized(); !ok {
		if r.FormValue("authorized") != "1" {
			site.Close()
			back("web.authorization_required")
			return
		}
		meta.AuthorizedAt, meta.AuthorizedBy = time.Now(), technician
	}
	id, err := engine.Begin(site, meta)
	if err != nil {
		site.Close()
		s.fail(w, r, 500, err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{Site: site.Slug, AuditID: id, Started: time.Now(), Status: "running", Phase: audit.PhaseDiscovery, cancel: cancel}
	s.jobs.add(j)
	go func() {
		defer site.Close()
		defer cancel()
		cfg, _ := config.Load(s.opt.DataDir)
		_, err := engine.Run(ctx, site, id, audit.Options{
			Targets: targets, Profile: profile, NoUDP: r.FormValue("no_udp") == "1", Rate: cfg.Rate, Progress: j.progress,
		})
		switch {
		case err == nil:
			j.finish("done", nil)
		case ctx.Err() != nil:
			j.finish("cancelled", err)
		default:
			j.finish("failed", err)
		}
	}()
	http.Redirect(w, r, "/sites/"+site.Slug+"/audits/"+itoa64(id), http.StatusSeeOther)
}

func (s *Server) cancelAudit(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r, "id")
	slug := store.Slugify(r.PathValue("slug"))
	if j := s.jobs.get(slug, id); j != nil && j.cancel != nil {
		j.cancel()
	}
	http.Redirect(w, r, "/sites/"+slug+"/audits/"+itoa64(id), http.StatusSeeOther)
}

func (s *Server) progress(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r, "id")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	j := s.jobs.get(store.Slugify(r.PathValue("slug")), id)
	if j == nil {
		json.NewEncoder(w).Encode(jobSnapshot{AuditID: id, Status: "unknown"})
		return
	}
	json.NewEncoder(w).Encode(j.snapshot())
}

// portCount : nombre d'appareils sur lesquels un port est ouvert.
type portCount struct {
	Key   string
	Name  string
	Count int
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	site, err := s.openSite(r)
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	defer site.Close()
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	a, err := site.GetAudit(id)
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	info, _ := site.Info()
	data := map[string]any{"Site": info, "Audit": a}
	if a.Status == store.StatusRunning {
		if j := s.jobs.get(site.Slug, id); j != nil {
			snap := j.snapshot()
			data["Job"] = &snap
		}
		s.render(w, r, "progress", data)
		return
	}
	obs, err := site.Observations(id)
	if err != nil {
		s.fail(w, r, 500, err)
		return
	}
	data["Observations"] = obs
	counts := map[string]*portCount{}
	types := map[string]int{}
	for _, o := range obs {
		t := o.DeviceType
		if t == "" {
			t = "unknown"
		}
		types[t]++
		for _, sv := range o.Services {
			pc := counts[sv.Key()]
			if pc == nil {
				pc = &portCount{Key: sv.Key(), Name: sv.Name}
				counts[sv.Key()] = pc
			}
			pc.Count++
		}
	}
	top := make([]portCount, 0, len(counts))
	for _, c := range counts {
		top = append(top, *c)
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].Key < top[j].Key
	})
	if len(top) > 10 {
		top = top[:10]
	}
	data["TopPorts"] = top
	findings, err := site.Findings(id)
	if err != nil {
		s.fail(w, r, 500, err)
		return
	}
	data["Findings"] = findings
	data["FindingCounts"] = store.FindingCounts(findings)
	perDevice := map[int64]findingSummary{}
	for _, f := range findings {
		fs := perDevice[f.DeviceID]
		switch f.Level {
		case "critical":
			fs.Critical++
			fs.Score += 100
		case "warning":
			fs.Warning++
			fs.Score += 10
		default:
			fs.Info++
			fs.Score++
		}
		perDevice[f.DeviceID] = fs
	}
	data["DeviceFindings"] = perDevice
	changes, err := site.Changes(id)
	if err != nil {
		s.fail(w, r, 500, err)
		return
	}
	data["Changes"] = changes
	isNew := map[int64]bool{}
	for _, c := range changes {
		if c.Kind == store.ChangeNewDevice {
			isNew[c.DeviceID] = true
		}
	}
	data["IsNew"] = isNew
	data["Saved"] = r.URL.Query().Get("saved")
	data["Langs"] = s.opt.Bundle.Languages()
	cfg, _ := config.Load(s.opt.DataDir)
	data["ReportLang"] = cfg.ReportLang
	data["Types"] = sortedCounts(types)
	if prev, _ := site.PreviousAudit(id); prev != 0 {
		if pa, err := site.GetAudit(prev); err == nil {
			data["Previous"] = pa
		}
	}
	s.render(w, r, "audit", data)
}

// findingSummary compte les points d'attention d'un appareil.
type findingSummary struct{ Critical, Warning, Info, Score int }

type kv struct {
	Key   string
	Count int
}

func sortedCounts(m map[string]int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func (s *Server) devicePage(w http.ResponseWriter, r *http.Request) {
	site, err := s.openSite(r)
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	defer site.Close()
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	dev, err := site.GetDevice(id)
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	hist, err := site.DeviceHistory(id)
	if err != nil || len(hist) == 0 {
		s.fail(w, r, 404, errors.New("no observation"))
		return
	}
	audits := map[int64]store.Audit{}
	all, _ := site.Audits()
	for _, a := range all {
		audits[a.ID] = a
	}
	type histRow struct {
		Audit store.Audit
		Obs   store.Observation
	}
	var rows []histRow
	for i := len(hist) - 1; i >= 0; i-- {
		rows = append(rows, histRow{audits[hist[i].AuditID], hist[i]})
	}
	// Observation affichée : celle de l'audit demandé (?audit=), sinon la dernière.
	cur := hist[len(hist)-1]
	if q, err := strconv.ParseInt(r.URL.Query().Get("audit"), 10, 64); err == nil {
		for _, h := range hist {
			if h.AuditID == q {
				cur = h
			}
		}
	}
	info, _ := site.Info()
	all2, _ := site.Findings(cur.AuditID)
	var findings []store.Finding
	for _, f := range all2 {
		if f.DeviceID == id {
			findings = append(findings, f)
		}
	}
	s.render(w, r, "device", map[string]any{"Site": info, "Device": dev, "Obs": cur, "History": rows, "Audit": audits[cur.AuditID], "Findings": findings})
}

// back renvoie vers la page indiquée par le champ « back » (chemin local).
func back(w http.ResponseWriter, r *http.Request, fallback string) {
	b := r.FormValue("back")
	if !strings.HasPrefix(b, "/") || strings.HasPrefix(b, "//") {
		b = fallback
	}
	http.Redirect(w, r, b, http.StatusSeeOther)
}

func (s *Server) annotate(w http.ResponseWriter, r *http.Request) {
	site, err := s.openSite(r)
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	defer site.Close()
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	if err := site.Annotate(id, r.FormValue("label"), r.FormValue("location"), r.FormValue("owner"), r.FormValue("notes")); err != nil {
		s.fail(w, r, 500, err)
		return
	}
	if err := site.SetKnown(id, r.FormValue("known") == "1"); err != nil {
		s.fail(w, r, 500, err)
		return
	}
	back(w, r, "/sites/"+site.Slug+"/devices/"+itoa64(id))
}

func (s *Server) setKnown(w http.ResponseWriter, r *http.Request) {
	site, err := s.openSite(r)
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	defer site.Close()
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	if err := site.SetKnown(id, r.FormValue("known") != "0"); err != nil {
		s.fail(w, r, 500, err)
		return
	}
	back(w, r, "/sites/"+site.Slug+"/devices/"+itoa64(id))
}

// reportData charge le rapport d'un audit et la langue demandée (?lang=).
func (s *Server) reportData(r *http.Request) (*store.Site, *report.Data, *i18n.Translator, string, error) {
	site, err := s.openSite(r)
	if err != nil {
		return nil, nil, nil, "", err
	}
	id, err := pathID(r, "id")
	if err != nil {
		site.Close()
		return nil, nil, nil, "", err
	}
	d, err := report.Build(site, id, "Arpent "+s.opt.Version)
	if err != nil {
		site.Close()
		return nil, nil, nil, "", err
	}
	cfg, _ := config.Load(s.opt.DataDir)
	d.Issuer = report.IssuerFromConfig(s.opt.DataDir, cfg.Issuer)
	lang := r.FormValue("lang")
	if !s.opt.Bundle.Has(lang) {
		if s.opt.Bundle.Has(cfg.ReportLang) {
			lang = cfg.ReportLang
		} else {
			lang = s.lang(r)
		}
	}
	format := r.FormValue("format")
	if !slices.Contains(report.Formats, format) {
		format = "html"
	}
	return site, d, s.opt.Bundle.Translator(lang), format, nil
}

func (s *Server) reportView(w http.ResponseWriter, r *http.Request) {
	site, d, tr, format, err := s.reportData(r)
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	defer site.Close()
	w.Header().Set("Content-Type", report.ContentType(format))
	if format != "html" || r.FormValue("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+report.FileName(d.Audit, format)+`"`)
	}
	// Le rapport contient un petit script (bouton Imprimer) : CSP propre.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
	if err := report.Write(w, format, d, tr); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (s *Server) reportSave(w http.ResponseWriter, r *http.Request) {
	site, d, tr, format, err := s.reportData(r)
	if err != nil {
		s.fail(w, r, 404, err)
		return
	}
	defer site.Close()
	path := report.Path(site, d.Audit, format)
	if err := report.WriteFile(path, format, d, tr); err != nil {
		s.fail(w, r, 500, err)
		return
	}
	http.Redirect(w, r, "/sites/"+site.Slug+"/audits/"+itoa64(d.Audit.ID)+"?saved="+url.QueryEscape(path), http.StatusSeeOther)
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	c, err := config.Load(s.opt.DataDir)
	if err != nil {
		s.fail(w, r, 500, err)
		return
	}
	is := report.IssuerFromConfig(s.opt.DataDir, c.Issuer)
	s.render(w, r, "settings", map[string]any{"C": c, "Profiles": portscan.Profiles, "DataDir": s.opt.DataDir,
		"LogoURI": is.LogoDataURI, "Saved": r.URL.Query().Get("saved") == "1"})
}

func (s *Server) saveSettings(w http.ResponseWriter, r *http.Request) {
	c, _ := config.Load(s.opt.DataDir)
	c.Technician = r.FormValue("technician")
	c.DefaultProfile = r.FormValue("default_profile")
	c.ReportLang = r.FormValue("report_lang")
	if !s.opt.Bundle.Has(c.ReportLang) {
		c.ReportLang = ""
	}
	c.Rate, _ = strconv.Atoi(r.FormValue("rate"))
	c.ReminderDays, _ = strconv.Atoi(r.FormValue("reminder_days"))
	c.Issuer = config.Issuer{Name: r.FormValue("issuer_name"), Company: r.FormValue("issuer_company"),
		Contact: r.FormValue("issuer_contact"), Legal: r.FormValue("issuer_legal"), Color: r.FormValue("issuer_color"),
		Logo: strings.TrimSpace(r.FormValue("issuer_logo"))}
	if c.Issuer.Color == "#1f5f8b" {
		c.Issuer.Color = "" // couleur par défaut : rien à enregistrer
	}
	if err := config.Save(s.opt.DataDir, c); err != nil {
		s.fail(w, r, 500, err)
		return
	}
	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}
