//go:build linux || darwin

package discovery

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var (
	pingOnce sync.Once
	pingOK   bool
)

// pingAvailable vérifie qu'un socket ICMP « non privilégié » est permis
// (Linux : net.ipv4.ping_group_range ; macOS : toujours).
func pingAvailable() bool {
	pingOnce.Do(func() {
		c, err := icmp.ListenPacket("udp4", "0.0.0.0")
		if err == nil {
			c.Close()
			pingOK = true
		}
	})
	return pingOK
}

func ping(ctx context.Context, ip netip.Addr, timeout time.Duration) (time.Duration, bool) {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return 0, false
	}
	defer c.Close()
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("arpent")}}
	b, _ := msg.Marshal(nil)
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	start := time.Now()
	if _, err := c.WriteTo(b, &net.UDPAddr{IP: ip.AsSlice()}); err != nil {
		return 0, false
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return 0, false
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || !ua.IP.Equal(ip.AsSlice()) {
			continue
		}
		m, err := icmp.ParseMessage(1, buf[:n])
		if err == nil && m.Type == ipv4.ICMPTypeEchoReply {
			return time.Since(start), true
		}
	}
}
