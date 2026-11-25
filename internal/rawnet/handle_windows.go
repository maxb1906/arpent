package rawnet

import (
	"errors"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"
)

// Windows : Npcap (wpcap.dll chargée dynamiquement par gopacket, sans CGO).
// Npcap n'est pas embarqué : sa licence gratuite n'autorise pas la
// redistribution ; on détecte sa présence.

var procIsUserAnAdmin = syscall.NewLazyDLL("shell32.dll").NewProc("IsUserAnAdmin")

func isAdmin() bool {
	if procIsUserAnAdmin.Find() != nil {
		return false
	}
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

func check() Status {
	if err := pcap.LoadWinPCAP(); err != nil {
		return Status{Reason: "advanced.reason.npcap"}
	}
	if !isAdmin() {
		return Status{Reason: "advanced.reason.admin"}
	}
	return Status{Available: true, Driver: "npcap"}
}

type winHandle struct{ h *pcap.Handle }

func open(ifc Iface) (Handle, error) {
	if err := pcap.LoadWinPCAP(); err != nil {
		return nil, err
	}
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	// Les noms Npcap (\Device\NPF_{GUID}) ne correspondent pas aux noms
	// Windows : on retrouve l'interface par son adresse IPv4.
	for _, d := range devs {
		for _, a := range d.Addresses {
			if ip4 := a.IP.To4(); ip4 != nil && ip4.Equal(ifc.IP.AsSlice()) {
				h, err := pcap.OpenLive(d.Name, 65536, false, 200*time.Millisecond)
				if err != nil {
					return nil, err
				}
				return &winHandle{h}, nil
			}
		}
	}
	return nil, errors.New("rawnet: interface Npcap introuvable pour " + ifc.IP.String())
}

func (w *winHandle) WritePacket(f []byte) error { return w.h.WritePacketData(f) }

func (w *winHandle) ReadPacket(d time.Duration) ([]byte, error) {
	deadline := time.Now().Add(d)
	for {
		data, _, err := w.h.ReadPacketData()
		if err == nil {
			return append([]byte(nil), data...), nil
		}
		if !errors.Is(err, pcap.NextErrorTimeoutExpired) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, ErrTimeout
		}
	}
}

func (w *winHandle) Close() error { w.h.Close(); return nil }
