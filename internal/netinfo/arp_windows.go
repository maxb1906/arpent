package netinfo

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

const activeARPSupported = true

var (
	iphlpapi          = syscall.NewLazyDLL("iphlpapi.dll")
	procGetIpNetTable = iphlpapi.NewProc("GetIpNetTable2")
	procFreeMibTable  = iphlpapi.NewProc("FreeMibTable")
	procSendARP       = iphlpapi.NewProc("SendARP")
)

func arpTable() ([]Neighbor, error) {
	if err := procGetIpNetTable.Find(); err != nil {
		return nil, err
	}
	var table *byte // MIB_IPNET_TABLE2 alloué par Windows
	r, _, _ := procGetIpNetTable.Call(afInet, uintptr(unsafe.Pointer(&table)))
	if r != 0 {
		return nil, fmt.Errorf("GetIpNetTable2 : %w", syscall.Errno(r))
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))
	n := *(*uint32)(unsafe.Pointer(table))
	rows := unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(table), ipnetTable2Head)), int(n)*ipnetRow2Size)
	out := make([]Neighbor, 0, n)
	for i := 0; i < int(n); i++ {
		if nb, ok := parseIPNetRow2(rows[i*ipnetRow2Size : (i+1)*ipnetRow2Size]); ok {
			out = append(out, nb)
		}
	}
	return out, nil
}

// errNoReply : ERROR_BAD_NET_NAME (67) ou ERROR_GEN_FAILURE (31), renvoyées
// par SendARP quand personne ne répond.
var errNoReply = errors.New("pas de réponse ARP")

func activeARP(ctx context.Context, ip netip.Addr) (net.HardwareAddr, error) {
	if !ip.Is4() {
		return nil, ErrNotSupported
	}
	if err := procSendARP.Find(); err != nil {
		return nil, err
	}
	type result struct {
		mac net.HardwareAddr
		err error
	}
	ch := make(chan result, 1)
	go func() {
		b := ip.As4()
		dest := *(*uint32)(unsafe.Pointer(&b[0])) // IPAddr = in_addr, ordre réseau
		var buf [8]byte
		l := uint32(len(buf))
		r, _, _ := procSendARP.Call(uintptr(dest), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)))
		switch {
		case r == 67 || r == 31:
			ch <- result{err: errNoReply}
		case r != 0:
			ch <- result{err: fmt.Errorf("SendARP : %w", syscall.Errno(r))}
		case l != 6 || !validMAC(buf[:6]):
			ch <- result{err: errNoReply}
		default:
			ch <- result{mac: net.HardwareAddr(append([]byte(nil), buf[:6]...))}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.mac, res.err
	}
}
