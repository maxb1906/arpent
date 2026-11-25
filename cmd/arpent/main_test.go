package main

import (
	"bytes"
	"context"
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
		{[]string{"--lang", "fr"}, 0, "Bonjour depuis Arpent"},
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
