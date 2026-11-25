//go:build !linux && !darwin && !windows

package discovery

import (
	"context"
	"net/netip"
	"time"
)

func pingAvailable() bool { return false }

func ping(context.Context, netip.Addr, time.Duration) (time.Duration, bool) { return 0, false }
