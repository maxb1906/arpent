package web

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/maxb1906/arpent/internal/report"
)

// TestRealBrowserForm soumet un formulaire depuis un vrai navigateur (Edge,
// Chrome) : les en-têtes Origin / Sec-Fetch-Site / Referrer-Policy réels ne
// sont pas reproduits par le client HTTP de Go.
func TestRealBrowserForm(t *testing.T) {
	path, err := report.FindBrowser()
	if errors.Is(err, report.ErrNoBrowser) {
		if os.Getenv("ARPENT_REQUIRE_BROWSER") != "" {
			t.Fatal("navigateur exigé (CI) mais introuvable")
		}
		t.Skip("aucun navigateur Chromium sur cette machine")
	}
	h := start(t)
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(path),
		chromedp.UserDataDir(filepath.Join(t.TempDir(), "profil")),
		chromedp.Flag("no-first-run", true),
	)
	actx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	bctx, cancel2 := chromedp.NewContext(actx)
	defer cancel2()
	ctx, cancel3 := context.WithTimeout(bctx, 90*time.Second)
	defer cancel3()

	if err := chromedp.Do(bctx, chromedp.Navigate(h.srv.URL())); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Do(ctx,
		chromedp.WaitVisible(chromedp.CSS(`form[action="/sites"] input[name="name"]`)),
		chromedp.SendKeys(chromedp.CSS(`form[action="/sites"] input[name="name"]`), "Test navigateur"),
		chromedp.Submit(chromedp.CSS(`form[action="/sites"] input[name="name"]`)),
	); err != nil {
		t.Fatal(err)
	}
	var loc, body string
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		loc, _ = chromedp.Run(ctx, chromedp.Location())
		body, _ = chromedp.Run(ctx, chromedp.Evaluate[string](`document.body ? document.body.innerText : ""`))
		if strings.Contains(loc, "/sites/") || strings.Contains(body, "forbidden") || ctx.Err() != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if strings.Contains(body, "forbidden") || !strings.Contains(loc, "/sites/") {
		t.Fatalf("formulaire refusé : %s\n%s", loc, body)
	}
	if !strings.Contains(body, "Test navigateur") {
		t.Errorf("page du site inattendue : %s", body)
	}
}
