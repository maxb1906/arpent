package i18n

import (
	"strings"
	"testing"
	"testing/fstest"
)

// Toutes les langues embarquées doivent avoir exactement les mêmes clés,
// et aucune traduction ne doit être vide.
func TestEmbeddedCatalogsAreComplete(t *testing.T) {
	b, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fr", "en"} {
		if !b.Has(want) {
			t.Fatalf("langue %q absente", want)
		}
	}
	ref := b.Keys(Fallback)
	for _, lang := range b.Languages() {
		keys := b.Keys(lang)
		if strings.Join(keys, ",") != strings.Join(ref, ",") {
			t.Errorf("%s : clés différentes de %s\n%s: %v\n%s: %v", lang, Fallback, lang, keys, Fallback, ref)
		}
		tr := b.Translator(lang)
		for _, k := range keys {
			if strings.TrimSpace(tr.T(k)) == "" {
				t.Errorf("%s : traduction vide pour %q", lang, k)
			}
		}
	}
}

func testBundle(t *testing.T) *Bundle {
	t.Helper()
	fsys := fstest.MapFS{
		"i18n/fr.json": {Data: []byte(`{"a":"Bonjour {nom}","only_fr":"seulement fr"}`)},
		"i18n/en.json": {Data: []byte(`{"a":"Hello {nom}"}`)},
	}
	b, err := Load(fsys, "i18n")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTranslate(t *testing.T) {
	b := testBundle(t)
	cases := []struct{ lang, key, want string }{
		{"fr", "a", "Bonjour Ada"},
		{"en", "a", "Hello Ada"},
		{"en", "only_fr", "seulement fr"}, // repli sur la langue par défaut
		{"en", "missing", "missing"},      // clé absente renvoyée telle quelle
		{"de", "a", "Bonjour Ada"},        // langue inconnue → repli
	}
	for _, c := range cases {
		if got := b.Translator(c.lang).T(c.key, "nom", "Ada"); got != c.want {
			t.Errorf("T(%s, %s) = %q, attendu %q", c.lang, c.key, got, c.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"fr_BE.UTF-8": "fr", "en-US": "en", "EN": "en", "C": "", "POSIX": "", "": "", "de_DE@euro": "de",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, attendu %q", in, got, want)
		}
	}
}

func TestDetect(t *testing.T) {
	b := testBundle(t)
	for _, v := range []string{"ARPENT_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		t.Setenv(v, "")
	}
	t.Setenv("LANG", "en_GB.UTF-8")
	if got := b.Detect(); got != "en" {
		t.Errorf("Detect avec LANG=en_GB = %q, attendu en", got)
	}
	t.Setenv("ARPENT_LANG", "fr")
	if got := b.Detect(); got != "fr" {
		t.Errorf("ARPENT_LANG doit primer : %q", got)
	}
	t.Setenv("ARPENT_LANG", "")
	t.Setenv("LANG", "de_DE.UTF-8")
	if got := b.Detect(); got != Fallback && got != "en" {
		t.Errorf("langue non disponible : %q", got)
	}
}
