package pace

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestLimiterRate(t *testing.T) {
	l := New(200) // 5 ms par opération, rafale de 8
	ctx := context.Background()
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 48; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); l.Wait(ctx) }()
	}
	wg.Wait()
	// 48 opérations − 8 de rafale = 40 × 5 ms = 200 ms minimum.
	if d := time.Since(start); d < 180*time.Millisecond || d > 2*time.Second {
		t.Errorf("durée %v, attendu ≈ 200 ms", d)
	}
}

func TestNilAndCancel(t *testing.T) {
	var l *Limiter
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	l = New(1)
	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < 8; i++ {
		l.Wait(ctx) // rafale
	}
	cancel()
	if err := l.Wait(ctx); err == nil {
		t.Error("Wait aurait dû être annulé")
	}
}
