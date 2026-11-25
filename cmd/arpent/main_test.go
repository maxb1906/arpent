package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, &out, &errOut)
	return code, out.String() + errOut.String()
}

func TestRun(t *testing.T) {
	cases := []struct {
		args     []string
		code     int
		contains string
	}{
		{[]string{"--lang", "fr", "hello"}, 0, "Bonjour depuis Arpent"},
		{[]string{"--lang", "en", "hello"}, 0, "Hello from Arpent"},
		{[]string{"version"}, 0, "dev"},
		{[]string{"--lang", "en", "nope"}, 2, "Unknown command: nope"},
		{[]string{"--lang", "xx"}, 2, "xx"},
		{[]string{"--lang", "en", "-h"}, 0, "Usage: arpent"},
		{[]string{"--lang", "en", "help"}, 0, "interfaces"},
		{[]string{"--lang", "en", "interfaces"}, 0, "Interface"},
		{[]string{"--lang", "en", "interfaces", "-h"}, 0, "--all"},
		{[]string{"--lang", "en", "interfaces", "--bogus"}, 2, "Error:"},
		{[]string{"--lang", "fr", "arp"}, 0, "voisin(s)"},
	}
	for _, c := range cases {
		code, all := runCLI(t, c.args...)
		if code != c.code {
			t.Errorf("%v : code %d, attendu %d (%s)", c.args, code, c.code, all)
		}
		if !strings.Contains(all, c.contains) {
			t.Errorf("%v : sortie %q ne contient pas %q", c.args, all, c.contains)
		}
	}
}

// Chaque commande et chaque option doit avoir sa traduction.
func TestHelpIsTranslated(t *testing.T) {
	for _, lang := range []string{"fr", "en"} {
		for _, c := range order {
			if _, ok := commands[c]; !ok {
				t.Errorf("commande %q dans order mais pas enregistrée", c)
			}
			_, out := runCLI(t, "--lang", lang, c, "-h")
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "flag.") || strings.Contains(line, "cmd.") {
					t.Errorf("%s %s : clé non traduite : %q", lang, c, line)
				}
			}
		}
		_, out := runCLI(t, "--lang", lang, "help")
		if strings.Contains(out, "cmd.") {
			t.Errorf("%s : aide non traduite : %s", lang, out)
		}
	}
}

func TestPortsFullNeedsConfirmation(t *testing.T) {
	old := stdin
	defer func() { stdin = old }()
	stdin = strings.NewReader("n\n")
	code, out := runCLI(t, "--lang", "en", "ports", "--profile", "full", "--range", "127.0.0.1")
	if code != 1 || !strings.Contains(out, "Cancelled") {
		t.Errorf("code %d : %s", code, out)
	}
}

func TestPortsLoopback(t *testing.T) {
	code, out := runCLI(t, "--lang", "en", "ports", "--profile", "quick", "--range", "127.0.0.1", "--no-discover", "--no-udp")
	if code != 0 || !strings.Contains(out, "127.0.0.1") {
		t.Errorf("code %d : %s", code, out)
	}
}

func TestScanSaveAndShow(t *testing.T) {
	data := t.TempDir()
	old := stdin
	defer func() { stdin = old }()

	// Sans confirmation : refus.
	stdin = strings.NewReader("\n")
	code, out := runCLI(t, "--lang", "en", "--data", data, "scan", "--site", "Café Test", "--range", "127.0.0.1", "--profile", "quick", "--no-discover", "--no-udp")
	if code != 1 || !strings.Contains(out, "illegal") {
		t.Fatalf("code %d : %s", code, out)
	}
	stdin = strings.NewReader("y\n")
	code, out = runCLI(t, "--lang", "en", "--data", data, "scan", "--site", "Café Test", "--technician", "Max", "--range", "127.0.0.1", "--profile", "quick", "--no-discover", "--no-udp")
	if code != 0 || !strings.Contains(out, "saved in site \"cafe-test\"") {
		t.Fatalf("code %d : %s", code, out)
	}
	// Second audit : plus de question.
	stdin = strings.NewReader("")
	if code, out = runCLI(t, "--data", data, "scan", "--site", "cafe-test", "--range", "127.0.0.1", "--profile", "quick", "--no-discover", "--no-udp"); code != 0 {
		t.Fatalf("code %d : %s", code, out)
	}
	if code, out = runCLI(t, "--lang", "en", "--data", data, "sites"); code != 0 || !strings.Contains(out, "Café Test") {
		t.Errorf("sites : %s", out)
	}
	if code, out = runCLI(t, "--lang", "en", "--data", data, "audits", "--site", "Café Test"); code != 0 || !strings.Contains(out, "done") || !strings.Contains(out, "Max") {
		t.Errorf("audits : %s", out)
	}
	if code, out = runCLI(t, "--lang", "en", "--data", data, "show", "--site", "Café Test"); code != 0 || !strings.Contains(out, "Audit #2") || !strings.Contains(out, "127.0.0.1") {
		t.Errorf("show : %s", out)
	}
	if code, out = runCLI(t, "--lang", "en", "--data", data, "annotate", "--site", "Café Test", "--ip", "127.0.0.1", "--label", "Devbox", "--known"); code != 0 {
		t.Errorf("annotate : %d %s", code, out)
	}
	if code, out = runCLI(t, "--lang", "en", "--data", data, "show", "--site", "Café Test"); !strings.Contains(out, "Devbox") {
		t.Errorf("annotation absente : %s", out)
	}
	if code, _ = runCLI(t, "--data", data, "annotate", "--site", "Café Test", "--ip", "10.9.9.9"); code != 1 {
		t.Errorf("appareil inconnu : code %d", code)
	}
	if code, out = runCLI(t, "--lang", "en", "--data", data, "report", "--site", "Café Test", "--report-lang", "fr"); code != 0 || !strings.Contains(out, "rapports") {
		t.Errorf("report : %d %s", code, out)
	}
	if code, out = runCLI(t, "--data", data, "report", "--site", "Café Test", "--format", "json", "--out", "-"); code != 0 || !strings.Contains(out, `"devices"`) {
		t.Errorf("report json : %d %s", code, out)
	}
	if code, out = runCLI(t, "--lang", "en", "--data", data, "compare", "--site", "Café Test"); code != 0 || !strings.Contains(out, "audit #1 and audit #2") {
		t.Errorf("compare : %d %s", code, out)
	}
	arc := filepath.Join(t.TempDir(), "cafe.arpent")
	if code, out = runCLI(t, "--lang", "en", "--data", data, "export", "--site", "Café Test", "--out", arc); code != 0 {
		t.Errorf("export : %d %s", code, out)
	}
	data2 := t.TempDir()
	if code, out = runCLI(t, "--lang", "en", "--data", data2, "import", arc); code != 0 || !strings.Contains(out, "2 audit(s) added") {
		t.Errorf("import : %d %s", code, out)
	}
	if code, out = runCLI(t, "--lang", "en", "--data", data2, "search", "Devbox"); code != 0 || !strings.Contains(out, "Café Test") {
		t.Errorf("search : %d %s", code, out)
	}
	if code, _ = runCLI(t, "--data", data, "show", "--site", "absent"); code != 1 {
		t.Errorf("site absent : code %d", code)
	}
}
