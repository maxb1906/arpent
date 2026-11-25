package probe

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/maxb1906/arpent/internal/pace"
)

// Target est un port TCP ouvert à sonder.
type Target struct {
	IP   netip.Addr
	Port int
}

// All sonde les cibles en parallèle (workers, débit en sondes/s) et renvoie
// les services dans le même ordre que targets.
func All(ctx context.Context, targets []Target, workers, rate int, opt Options, progress func(done, total int)) []Service {
	if workers <= 0 {
		workers = 32
	}
	lim := pace.New(rate)
	out := make([]Service, len(targets))
	var (
		wg   sync.WaitGroup
		done atomic.Int64
	)
	idx := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				if lim.Wait(ctx) == nil {
					out[i] = TCP(ctx, targets[i].IP, targets[i].Port, opt)
				}
				if progress != nil {
					progress(int(done.Add(1)), len(targets))
				}
			}
		}()
	}
	for i := range targets {
		select {
		case idx <- i:
		case <-ctx.Done():
		}
	}
	close(idx)
	wg.Wait()
	return out
}
