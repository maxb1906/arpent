package fingerprint

import (
	"testing"

	"github.com/maxb1906/arpent/internal/i18n"
)

func TestGuess(t *testing.T) {
	sigs := DefaultSignatures()
	cases := []struct {
		name    string
		e       Evidence
		want    string
		product string
	}{
		{"imprimante HP", Evidence{Vendor: "HP Inc.", Ports: []string{"80/tcp", "443/tcp", "631/tcp", "9100/tcp"}, HTTPTitles: []string{"HP LaserJet Pro M404"}}, "printer", ""},
		{"NAS QNAP", Evidence{Vendor: "QNAP Systems, Inc.", Ports: []string{"80/tcp", "443/tcp", "445/tcp", "8080/tcp"}, HTTPTitles: []string{"QTS"}}, "nas", "QNAP NAS"},
		{"Proxmox", Evidence{Vendor: "Intel Corporate", Ports: []string{"22/tcp", "8006/tcp"}, HTTPTitles: []string{"pve - Proxmox Virtual Environment"}}, "hypervisor", "Proxmox VE"},
		{"box internet", Evidence{Vendor: "Sagemcom Broadband SAS", Ports: []string{"53/tcp", "80/tcp", "443/tcp", "53/udp", "1900/udp"}, HTTPTitles: []string{"Livebox"}, SSDP: "Livebox | Sagemcom | urn:schemas-upnp-org:device:InternetGatewayDevice:1"}, "router", ""},
		{"PC Windows", Evidence{Vendor: "Dell Inc.", Ports: []string{"135/tcp", "139/tcp", "445/tcp", "137/udp"}, NetBIOS: true}, "pc", ""},
		{"iPhone", Evidence{RandomMAC: true, Ports: []string{"62078/tcp"}}, "phone", "iPhone / iPad"},
		{"caméra Tapo", Evidence{Vendor: "TP-LINK TECHNOLOGIES CO.,LTD.", Ports: []string{"554/tcp", "2020/tcp"}}, "camera", ""},
		{"NVIDIA Shield", Evidence{Vendor: "NVIDIA", Ports: []string{"8008/tcp", "8009/tcp", "8443/tcp"}, MDNS: []string{"_googlecast._tcp.local"}}, "tv", ""},
		{"Raspberry Pi", Evidence{Vendor: "Raspberry Pi Trading Ltd", Ports: []string{"22/tcp"}, Products: []string{"OpenSSH"}}, "server", "Raspberry Pi"},
		{"Home Assistant", Evidence{Ports: []string{"8123/tcp"}}, "smart_home", "Home Assistant"},
		{"inconnu", Evidence{Ports: []string{"12345/tcp"}}, "", ""},
	}
	for _, c := range cases {
		got, product := Guess(sigs, c.e)
		if got != c.want || (c.product != "" && product != c.product) {
			t.Errorf("%s : %q / %q, attendu %q / %q", c.name, got, product, c.want, c.product)
		}
	}
}

func TestSignaturesValid(t *testing.T) {
	if len(DefaultSignatures()) < 50 {
		t.Errorf("%d signatures seulement", len(DefaultSignatures()))
	}
	if _, err := LoadSignatures([]byte(`- { type: toaster, weight: 1 }`)); err == nil {
		t.Error("type inconnu accepté")
	}
	if _, err := LoadSignatures([]byte(`- { type: pc, vendor: "(" }`)); err == nil {
		t.Error("expression invalide acceptée")
	}
}

func TestTypesTranslated(t *testing.T) {
	b, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, lang := range b.Languages() {
		for _, ty := range append(Types, "unknown") {
			if k := "type." + ty; b.Translator(lang).T(k) == k {
				t.Errorf("%s : %s non traduit", lang, k)
			}
		}
	}
}
