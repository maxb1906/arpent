package report

import (
	"bytes"
	"context"
	"errors"
	"html"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/maxb1906/arpent/internal/i18n"
)

// ErrNoBrowser : aucun navigateur Chromium (Edge, Chrome, Chromium) trouvé.
var ErrNoBrowser = errors.New("aucun navigateur Edge/Chrome/Chromium trouvé")

// browserCandidates liste les emplacements habituels, par ordre de préférence.
func browserCandidates() []string {
	switch runtime.GOOS {
	case "windows":
		var out []string
		for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles", "LocalAppData"} {
			base := os.Getenv(env)
			if base == "" {
				continue
			}
			out = append(out,
				filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
				filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe"),
				filepath.Join(base, "Chromium", "Application", "chrome.exe"),
				filepath.Join(base, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"))
		}
		return out
	case "darwin":
		return []string{
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	default:
		var out []string
		for _, n := range []string{"microsoft-edge", "microsoft-edge-stable", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
			if p, err := exec.LookPath(n); err == nil {
				out = append(out, p)
			}
		}
		return append(out, "/snap/bin/chromium")
	}
}

// FindBrowser renvoie le chemin d'un navigateur Chromium installé ; la
// variable ARPENT_BROWSER permet d'en imposer un.
func FindBrowser() (string, error) {
	if p := os.Getenv("ARPENT_BROWSER"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	for _, p := range browserCandidates() {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", ErrNoBrowser
}

// PDF produit le rapport en PDF à partir du même modèle HTML, en pilotant
// le navigateur sans fenêtre (protocole DevTools), avec en-têtes et pieds
// de page : site, date, numéro de page, mention de confidentialité.
func PDF(ctx context.Context, d *Data, tr *i18n.Translator) ([]byte, error) {
	browser, err := FindBrowser()
	if err != nil {
		return nil, err
	}
	// Limite globale : au-delà, le navigateur est arrêté.
	ctx, cancelAll := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelAll()
	tmp, err := os.MkdirTemp("", "arpent-pdf-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	htmlPath := filepath.Join(tmp, "rapport.html")
	var buf bytes.Buffer
	if err := HTML(&buf, d, tr); err != nil {
		return nil, err
	}
	if err := os.WriteFile(htmlPath, buf.Bytes(), 0o600); err != nil {
		return nil, err
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(browser),
		chromedp.UserDataDir(filepath.Join(tmp, "profil")), // profil jetable : rien n'est laissé chez l'utilisateur
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("no-first-run", true),
	)
	actx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()
	bctx, cancel2 := chromedp.NewContext(actx)
	defer cancel2()
	tctx, cancel3 := context.WithTimeout(bctx, 90*time.Second)
	defer cancel3()

	site, date := html.EscapeString(d.Site.Name), html.EscapeString(d.Audit.Started.Local().Format("2006-01-02"))
	if tr.Lang() == "fr" {
		date = html.EscapeString(d.Audit.Started.Local().Format("02/01/2006"))
	}
	style := `font-family: 'Segoe UI', Arial, sans-serif; font-size: 7.5px; color: #5d6b78; width: 100%; padding: 0 14mm; display: flex; justify-content: space-between;`
	header := `<div style="` + style + `"><span>` + site + `</span><span>` + html.EscapeString(tr.T("report.title")) + ` — ` + date + `</span></div>`
	footer := `<div style="` + style + `"><span>` + html.EscapeString(tr.T("report.pdf_confidential")) + `</span><span>` +
		html.EscapeString(tr.T("report.pdf_page")) + ` <span class="pageNumber"></span> / <span class="totalPages"></span></span></div>`

	fileURL := (&url.URL{Scheme: "file", Path: filepath.ToSlash(htmlPath)}).String()
	if runtime.GOOS == "windows" {
		fileURL = "file:///" + filepath.ToSlash(htmlPath)
	}
	// Premier appel sans délai (il démarre le navigateur), puis délai sur l'impression.
	if err := chromedp.Do(bctx, chromedp.Navigate(fileURL)); err != nil {
		return nil, err
	}
	if err := chromedp.Do(tctx, chromedp.WaitReady(chromedp.CSS("body"))); err != nil {
		return nil, err
	}
	pdf, err := chromedp.Run(tctx, chromedp.PrintToPDF(
		chromedp.PDFPaper(chromedp.PaperA4),
		chromedp.PDFMargins(0.75, 0.4, 0.75, 0.4), // pouces : place pour l'en-tête et le pied
		chromedp.PDFPrintBackground(),
		chromedp.PDFHeaderTemplate(header),
		chromedp.PDFFooterTemplate(footer),
	))
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF")) {
		return nil, errors.New("le navigateur n'a pas produit de PDF")
	}
	return pdf, nil
}

// PDFFile écrit le PDF du rapport dans path.
func PDFFile(ctx context.Context, path string, d *Data, tr *i18n.Translator) error {
	b, err := PDF(ctx, d, tr)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
