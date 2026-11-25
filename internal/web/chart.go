package web

import (
	"fmt"
	"html/template"
	"math"
	"strings"
)

// point est une valeur d'une série chronologique (un audit).
type point struct {
	Label string // date de l'audit
	Value int
}

// niceMax arrondit le maximum de l'axe à une valeur ronde (au moins 4).
func niceMax(v int) int {
	if v <= 4 {
		return 4
	}
	mag := math.Pow(10, math.Floor(math.Log10(float64(v))))
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if float64(v) <= m*mag {
			return int(m * mag)
		}
	}
	return v
}

// lineChart dessine une petite courbe (une seule série, un seul axe) en SVG.
// Les couleurs viennent des variables CSS (thème clair/sombre) ; chaque point
// a une infobulle native et la dernière valeur est étiquetée directement.
func lineChart(title string, pts []point) template.HTML {
	const w, h, left, right, top, bottom = 320.0, 140.0, 34.0, 34.0, 14.0, 26.0
	if len(pts) == 0 {
		return ""
	}
	maxV := 0
	for _, p := range pts {
		maxV = max(maxV, p.Value)
	}
	ymax := float64(niceMax(maxV))
	pw, ph := w-left-right, h-top-bottom
	x := func(i int) float64 {
		if len(pts) == 1 {
			return left + pw/2
		}
		return left + pw*float64(i)/float64(len(pts)-1)
	}
	y := func(v int) float64 { return top + ph - ph*float64(v)/ymax }
	esc := template.HTMLEscapeString

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart" viewBox="0 0 %.0f %.0f" role="img" aria-label="%s">`, w, h, esc(title))
	// Grille discrète : 0, moitié, maximum.
	for _, g := range []float64{0, ymax / 2, ymax} {
		gy := top + ph - ph*g/ymax
		fmt.Fprintf(&b, `<line class="grid" x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f"/>`, left, w-right, gy, gy)
		fmt.Fprintf(&b, `<text class="axis" x="%.1f" y="%.1f" text-anchor="end">%s</text>`, left-6, gy+3.5, trimFloat(g))
	}
	// Dates de début et de fin seulement (les autres dans les infobulles).
	fmt.Fprintf(&b, `<text class="axis" x="%.1f" y="%.1f" text-anchor="start">%s</text>`, x(0), h-6, esc(pts[0].Label))
	if len(pts) > 1 {
		fmt.Fprintf(&b, `<text class="axis" x="%.1f" y="%.1f" text-anchor="end">%s</text>`, x(len(pts)-1), h-6, esc(pts[len(pts)-1].Label))
	}
	if len(pts) > 1 {
		var d strings.Builder
		for i, p := range pts {
			fmt.Fprintf(&d, "%s%.1f %.1f", map[bool]string{true: "M", false: " L"}[i == 0], x(i), y(p.Value))
		}
		fmt.Fprintf(&b, `<path class="line" d="%s"/>`, d.String())
	}
	for i, p := range pts {
		// Zone de survol plus large que le point.
		fmt.Fprintf(&b, `<g class="pt"><circle class="hit" cx="%.1f" cy="%.1f" r="11"/><circle class="dot" cx="%.1f" cy="%.1f" r="4"/><title>%s : %d</title></g>`,
			x(i), y(p.Value), x(i), y(p.Value), esc(p.Label), p.Value)
	}
	last := pts[len(pts)-1]
	fmt.Fprintf(&b, `<text class="value" x="%.1f" y="%.1f">%d</text>`, x(len(pts)-1)+8, y(last.Value)+4, last.Value)
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

func trimFloat(f float64) string {
	if f == math.Trunc(f) {
		return fmt.Sprint(int(f))
	}
	return fmt.Sprintf("%.1f", f)
}
