// Package engine exécute un audit et l'enregistre dans un site : début,
// phases de l'audit, sauvegarde, puis analyses qui s'appuient sur la base
// (points d'attention, comparaison avec l'audit précédent). La CLI et
// l'interface web passent toutes deux par ici.
package engine

import (
	"context"
	"errors"

	"github.com/maxb1906/arpent/internal/audit"
	"github.com/maxb1906/arpent/internal/diff"
	"github.com/maxb1906/arpent/internal/rules"
	"github.com/maxb1906/arpent/internal/store"
)

// PhaseSave est la phase finale (enregistrement et analyses).
const PhaseSave = "save"

// PostProcessor analyse un audit enregistré (règles, diff…).
type PostProcessor func(s *store.Site, auditID int64) error

// postProcessors : analyses exécutées dans l'ordre après chaque audit.
var postProcessors = []PostProcessor{rules.Apply, diff.Apply}

// Register ajoute une analyse exécutée après chaque audit enregistré.
func Register(p PostProcessor) { postProcessors = append(postProcessors, p) }

// DeviceType devine le type d'un appareil ; remplacé par fingerprint (étape 10).
var DeviceType func(audit.Host) string

// Begin enregistre l'audit « en cours » ; Run doit suivre.
func Begin(s *store.Site, meta store.AuditMeta) (int64, error) { return s.BeginAudit(meta) }

// Run exécute l'audit id déjà commencé, l'enregistre et lance les analyses.
func Run(ctx context.Context, s *store.Site, id int64, opt audit.Options) (*audit.Result, error) {
	res, err := audit.Run(ctx, opt)
	if err != nil {
		status := store.StatusFailed
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			status = store.StatusCancelled
		}
		s.EndAudit(id, status, err)
		return nil, err
	}
	if opt.Progress != nil {
		opt.Progress(PhaseSave, 0, 1)
	}
	if err := s.CompleteAudit(id, res, DeviceType); err != nil {
		s.EndAudit(id, store.StatusFailed, err)
		return nil, err
	}
	for _, p := range postProcessors {
		if err := p(s, id); err != nil {
			return res, err
		}
	}
	if opt.Progress != nil {
		opt.Progress(PhaseSave, 1, 1)
	}
	return res, nil
}
