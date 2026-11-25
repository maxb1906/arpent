// Package pace limite le débit des sondes réseau (paquets ou connexions par
// seconde) pour ne pas saturer les équipements fragiles du réseau audité.
package pace

import (
	"context"
	"sync"
	"time"
)

// Limiter autorise au plus Rate opérations par seconde, avec une petite
// rafale initiale. Un Limiter nil ou de débit ≤ 0 ne limite rien.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	burst    time.Duration
}

// New crée un limiteur de rate opérations par seconde.
func New(rate int) *Limiter {
	if rate <= 0 {
		return nil
	}
	iv := time.Second / time.Duration(rate)
	return &Limiter{interval: iv, burst: 8 * iv}
}

// Wait bloque jusqu'à ce qu'une opération soit autorisée, ou que ctx expire.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	if earliest := now.Add(-l.burst); l.next.Before(earliest) {
		l.next = earliest
	}
	at := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	d := time.Until(at)
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
