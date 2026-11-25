package i18n

import (
	"os"
	"strings"
)

// Detect choisit la langue de l'utilisateur parmi celles de b :
// variable ARPENT_LANG, puis LC_ALL, LC_MESSAGES, LANG, puis la langue du
// système (API Windows sous Windows), et enfin la langue de repli.
func (b *Bundle) Detect() string {
	candidates := []string{
		os.Getenv("ARPENT_LANG"),
		os.Getenv("LC_ALL"),
		os.Getenv("LC_MESSAGES"),
		os.Getenv("LANG"),
		systemLocale(),
	}
	for _, c := range candidates {
		if l := Normalize(c); l != "" && b.Has(l) {
			return l
		}
	}
	return Fallback
}

// Normalize réduit un identifiant de locale ("fr_BE.UTF-8", "en-US") à son
// code de langue ("fr", "en"). Les valeurs "C" et "POSIX" donnent "".
func Normalize(locale string) string {
	l := strings.ToLower(strings.TrimSpace(locale))
	if i := strings.IndexAny(l, "_-.@"); i >= 0 {
		l = l[:i]
	}
	if l == "c" || l == "posix" {
		return ""
	}
	return l
}
