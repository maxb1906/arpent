package report

import (
	"encoding/base64"
	"html/template"
	"mime"
	"os"
	"path/filepath"
	"strings"

	"github.com/maxb1906/arpent/internal/config"
)

// MaxLogoBytes limite la taille du logo intégré au rapport.
const MaxLogoBytes = 512 << 10

// IssuerFromConfig convertit le profil émetteur de config.yaml ; le logo est
// lu dans le dossier de données et intégré en data: URI.
func IssuerFromConfig(dataDir string, c config.Issuer) Issuer {
	is := Issuer{Name: c.Name, Company: c.Company, Contact: c.Contact, Legal: c.Legal, Color: c.Color}
	if c.Logo == "" {
		return is
	}
	path := filepath.Join(dataDir, filepath.FromSlash(c.Logo))
	st, err := os.Stat(path)
	if err != nil || st.Size() > MaxLogoBytes {
		return is
	}
	typ := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
	switch typ {
	case "image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml":
	default:
		return is
	}
	b, err := os.ReadFile(path)
	if err == nil {
		is.LogoDataURI = template.URL("data:" + typ + ";base64," + base64.StdEncoding.EncodeToString(b))
	}
	return is
}
