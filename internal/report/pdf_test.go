package report

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxb1906/arpent/internal/i18n"
)

func TestPDF(t *testing.T) {
	path, err := FindBrowser()
	if errors.Is(err, ErrNoBrowser) {
		if os.Getenv("ARPENT_REQUIRE_BROWSER") != "" {
			t.Fatal("navigateur exigé (CI) mais introuvable")
		}
		t.Skip("aucun navigateur Chromium sur cette machine")
	}
	t.Logf("navigateur : %s", path)
	s, id := site(t)
	d, err := Build(s, id, "Arpent test")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := i18n.Default()
	out := filepath.Join(t.TempDir(), "rapport.pdf")
	if err := PDFFile(context.Background(), out, d, b.Translator("fr")); err != nil {
		t.Fatal(err)
	}
	pdf, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) || len(pdf) < 10_000 {
		t.Errorf("PDF suspect : %d octets", len(pdf))
	}
	// Plusieurs pages attendues (garde, résumé, points, inventaire…).
	if n := bytes.Count(pdf, []byte("/Type /Page\n")) + bytes.Count(pdf, []byte("/Type /Page ")) + bytes.Count(pdf, []byte("/Type/Page")); n < 3 {
		t.Logf("pages détectées : %d (indicatif, selon le format interne du PDF)", n)
	}
}

func TestFindBrowserOverride(t *testing.T) {
	f := filepath.Join(t.TempDir(), "fake-browser")
	os.WriteFile(f, []byte("x"), 0o755)
	t.Setenv("ARPENT_BROWSER", f)
	if p, err := FindBrowser(); err != nil || p != f {
		t.Errorf("%q %v", p, err)
	}
}
