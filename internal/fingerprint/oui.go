// Package fingerprint identifie les appareils : fabricant d'après la MAC
// (base OUI de l'IEEE embarquée), puis signatures et type d'appareil.
package fingerprint

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"net"
	"strings"
	"sync"

	"github.com/maxb1906/arpent/assets"
)

var (
	ouiOnce sync.Once
	ouiMap  map[[3]byte]string
)

func loadOUI() {
	ouiMap = make(map[[3]byte]string, 41000)
	zr, err := gzip.NewReader(bytes.NewReader(assets.OUI))
	if err != nil {
		return
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		hex, name, ok := strings.Cut(sc.Text(), "\t")
		if !ok || len(hex) != 6 {
			continue
		}
		mac, err := net.ParseMAC(hex[0:2] + ":" + hex[2:4] + ":" + hex[4:6] + ":00:00:00")
		if err != nil {
			continue
		}
		ouiMap[[3]byte(mac[:3])] = name
	}
}

// Vendor renvoie le fabricant enregistré à l'IEEE pour le préfixe de mac,
// ou "" s'il est inconnu (ou si l'adresse est administrée localement).
func Vendor(mac net.HardwareAddr) string {
	if len(mac) < 3 || LocallyAdministered(mac) {
		return ""
	}
	ouiOnce.Do(loadOUI)
	return ouiMap[[3]byte(mac[:3])]
}

// LocallyAdministered indique une MAC administrée localement (bit 1 du
// premier octet) : typiquement une adresse aléatoire de téléphone ou de
// machine virtuelle, qui ne désigne pas de fabricant.
func LocallyAdministered(mac net.HardwareAddr) bool {
	return len(mac) > 0 && mac[0]&0x02 != 0
}

// OUICount renvoie le nombre de préfixes de la base embarquée.
func OUICount() int {
	ouiOnce.Do(loadOUI)
	return len(ouiMap)
}
