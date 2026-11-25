package netinfo

import (
	"context"
	"net"
	"net/netip"
	"os"
)

const activeARPSupported = false

func arpTable() ([]Neighbor, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseProcNetARP(f)
}

func activeARP(context.Context, netip.Addr) (net.HardwareAddr, error) {
	return nil, ErrNotSupported
}
