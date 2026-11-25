package rawnet

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// Linux : socket AF_PACKET (root ou CAP_NET_RAW), sans libpcap ni CGO.

const ethPAll = 0x0003

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func check() Status {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		if os.Geteuid() != 0 {
			return Status{Reason: "advanced.reason.root"}
		}
		return Status{Reason: "advanced.reason.socket"}
	}
	syscall.Close(fd)
	return Status{Available: true, Driver: "af_packet"}
}

type linuxHandle struct {
	fd  int
	ifc Iface
	buf []byte
}

func open(ifc Iface) (Handle, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifc.Index}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &linuxHandle{fd: fd, ifc: ifc, buf: make([]byte, 65536)}, nil
}

func (h *linuxHandle) WritePacket(f []byte) error {
	return syscall.Sendto(h.fd, f, 0, &syscall.SockaddrLinklayer{Ifindex: h.ifc.Index, Halen: 6})
}

func (h *linuxHandle) ReadPacket(d time.Duration) ([]byte, error) {
	tv := syscall.NsecToTimeval(d.Nanoseconds())
	syscall.SetsockoptTimeval(h.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	n, _, err := syscall.Recvfrom(h.fd, h.buf, 0)
	if err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
			return nil, ErrTimeout
		}
		return nil, err
	}
	return append([]byte(nil), h.buf[:n]...), nil
}

func (h *linuxHandle) Close() error { return syscall.Close(h.fd) }
