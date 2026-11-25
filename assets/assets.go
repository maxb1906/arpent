// Package assets regroupe les fichiers embarqués dans l'exécutable :
// traductions, et plus tard base OUI, signatures, règles, modèles et CSS/JS.
package assets

import "embed"

// I18n contient les fichiers de traduction assets/i18n/<langue>.json.
//
//go:embed i18n/*.json
var I18n embed.FS

// OUI est le registre IEEE MA-L compressé (« PREFIXE\tFabricant » par ligne),
// généré par tools/ouigen.
//
//go:embed oui.tsv.gz
var OUI []byte

// Web contient l'interface locale : web/templates/*.html et web/static/*.
//
//go:embed web
var Web embed.FS

// Rules contient les règles d'audit (points d'attention).
//
//go:embed rules.yaml
var Rules []byte

// Report contient le modèle du rapport (report/report.html, report.css).
//
//go:embed report
var Report embed.FS
