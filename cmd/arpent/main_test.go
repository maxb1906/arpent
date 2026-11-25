package main

import (
	"bytes"
	"strings"
	"testing"
)

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
	}
	for _, c := range cases {
		var out, errOut bytes.Buffer
		code := run(c.args, &out, &errOut)
		if code != c.code {
			t.Errorf("%v : code %d, attendu %d (stderr: %s)", c.args, code, c.code, errOut.String())
		}
		if all := out.String() + errOut.String(); !strings.Contains(all, c.contains) {
			t.Errorf("%v : sortie %q ne contient pas %q", c.args, all, c.contains)
		}
	}
}
