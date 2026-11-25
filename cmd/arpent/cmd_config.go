package main

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/maxb1906/arpent/internal/config"
)

// config charge config.yaml (une seule fois par exécution).
func (e *env) config() config.Config {
	if e.cfg == nil {
		c := config.Default()
		// Lecture seule : ne crée pas le dossier de données pour autant.
		if dir, err := config.Resolve(e.data); err == nil {
			if loaded, err := config.Load(dir); err == nil {
				c = loaded
			} else {
				fmt.Fprintln(e.stderr, e.T("cli.error", "error", err.Error()))
			}
		}
		e.cfg = &c
	}
	return *e.cfg
}

func cmdConfig(e *env, args []string) int {
	fs := e.newFlags("config")
	technician := fs.String("technician", "", "")
	profile := fs.String("profile", "", "")
	reportLang := fs.String("report-lang", "", "")
	lang := fs.String("ui-lang", "", "")
	company := fs.String("company", "", "")
	contact := fs.String("contact", "", "")
	logo := fs.String("logo", "", "")
	color := fs.String("color", "", "")
	reminder := fs.Int("reminder-days", 0, "")
	if code, ok := e.parse(fs, args); !ok {
		return code
	}
	dir, err := e.dataDir()
	if err != nil {
		return e.fail(err)
	}
	c, err := config.Load(dir)
	if err != nil {
		return e.fail(err)
	}
	changed := false
	fs.Visit(func(f *flag.Flag) {
		changed = true
		switch f.Name {
		case "technician":
			c.Technician = *technician
		case "profile":
			c.DefaultProfile = *profile
		case "report-lang":
			c.ReportLang = *reportLang
		case "ui-lang":
			c.Lang = *lang
		case "company":
			c.Issuer.Company = *company
		case "contact":
			c.Issuer.Contact = *contact
		case "logo":
			c.Issuer.Logo = *logo
		case "color":
			c.Issuer.Color = *color
		case "reminder-days":
			c.ReminderDays = *reminder
		}
	})
	if changed {
		if err := config.Save(dir, c); err != nil {
			return e.fail(err)
		}
		c, _ = config.Load(dir)
	}
	fmt.Fprintln(e.stdout, e.T("config.file", "path", filepath.Join(dir, config.FileName)))
	rows := [][2]string{
		{"technician", c.Technician}, {"profile", c.DefaultProfile}, {"report-lang", c.ReportLang}, {"ui-lang", c.Lang},
		{"company", c.Issuer.Company}, {"contact", c.Issuer.Contact}, {"logo", c.Issuer.Logo}, {"color", c.Issuer.Color},
		{"reminder-days", fmt.Sprint(c.ReminderDays)},
	}
	for _, r := range rows {
		fmt.Fprintf(e.stdout, "  %-14s %s\n", r[0], dash(r[1]))
	}
	return 0
}
