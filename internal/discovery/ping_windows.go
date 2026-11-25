package discovery

import (
	"context"
	"net/netip"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi            = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
)

// L'API ICMP de Windows (iphlpapi) n'exige pas de droits administrateur.
func pingAvailable() bool {
	return procIcmpCreateFile.Find() == nil && procIcmpSendEcho.Find() == nil
}

// icmpEchoReply reprend le début de ICMP_ECHO_REPLY (x64).
type icmpEchoReply struct {
	Address uint32
	Status  uint32
	RTT     uint32
}

func ping(ctx context.Context, ip netip.Addr, timeout time.Duration) (time.Duration, bool) {
	h, _, _ := procIcmpCreateFile.Call()
	if h == 0 || h == ^uintptr(0) {
		return 0, false
	}
	defer procIcmpCloseHandle.Call(h)
	if d, ok := ctx.Deadline(); ok && time.Until(d) < timeout {
		timeout = time.Until(d)
	}
	if timeout <= 0 {
		return 0, false
	}
	data := []byte("arpent")
	reply := make([]byte, 256)
	b := ip.As4()
	dest := *(*uint32)(unsafe.Pointer(&b[0]))
	start := time.Now()
	n, _, _ := procIcmpSendEcho.Call(h, uintptr(dest),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
	if n == 0 {
		return 0, false
	}
	r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	if r.Status != 0 || r.Address != dest { // IP_SUCCESS, réponse de la cible elle-même
		return 0, false
	}
	rtt := time.Duration(r.RTT) * time.Millisecond
	if rtt == 0 {
		rtt = time.Since(start)
	}
	return rtt, true
}
