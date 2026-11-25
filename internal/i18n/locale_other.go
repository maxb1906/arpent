//go:build !windows

package i18n

// systemLocale : hors Windows, la langue vient des variables d'environnement.
func systemLocale() string { return "" }
