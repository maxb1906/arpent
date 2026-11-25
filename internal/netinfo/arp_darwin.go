package netinfo

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os/exec"
)

const activeARPSupported = false

func arpTable() ([]Neighbor, error) {
	out, err := exec.Command("/usr/sbin/arp", "-an").Output()
	if err != nil {
		return nil, err
	}
	return parseArpAn(bytes.NewReader(out))
}

func activeARP(context.Context, netip.Addr) (net.HardwareAddr, error) {
	return nil, ErrNotSupported
}
