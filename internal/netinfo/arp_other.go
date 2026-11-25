//go:build !linux && !windows && !darwin

package netinfo

import (
	"context"
	"net"
	"net/netip"
)

const activeARPSupported = false

func arpTable() ([]Neighbor, error) { return nil, ErrNotSupported }

func activeARP(context.Context, netip.Addr) (net.HardwareAddr, error) {
	return nil, ErrNotSupported
}
