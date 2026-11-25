package fingerprint

import (
	"net"
	"strings"
	"testing"
)

func TestVendor(t *testing.T) {
	if n := OUICount(); n < 30000 {
		t.Fatalf("base OUI : %d préfixes seulement", n)
	}
	cases := map[string]string{
		"B8:27:EB:12:34:56": "Raspberry Pi",
		"24:5E:BE:00:00:01": "QNAP",
		"00:0A:EB:00:00:01": "TP-LINK",
	}
	for m, want := range cases {
		mac, _ := net.ParseMAC(m)
		if got := Vendor(mac); !strings.Contains(strings.ToUpper(got), strings.ToUpper(want)) {
			t.Errorf("Vendor(%s) = %q, attendu %q", m, got, want)
		}
	}
	rnd, _ := net.ParseMAC("DA:A1:19:00:00:01")
	if !LocallyAdministered(rnd) || Vendor(rnd) != "" {
		t.Error("MAC aléatoire mal reconnue")
	}
}
