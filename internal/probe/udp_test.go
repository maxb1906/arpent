package probe

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func nbName(name string, suffix byte, group bool) []byte {
	b := []byte((name + strings.Repeat(" ", 15))[:15])
	b = append(b, suffix)
	f := uint16(0x0400)
	if group {
		f |= 0x8000
	}
	return binary.BigEndian.AppendUint16(b, f)
}

func TestParseNBSTAT(t *testing.T) {
	resp := []byte{0x41, 0x52, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0, 0x20}
	resp = append(resp, []byte(strings.Repeat("CK", 1)+strings.Repeat("AA", 15))...)
	resp = append(resp, 0, 0, 0x21, 0, 1, 0, 0, 0, 0)
	names := [][]byte{nbName("PC-COMPTA", 0x00, false), nbName("BUREAU", 0x00, true), nbName("PC-COMPTA", 0x20, false), nbName("MARIE", 0x03, false)}
	var data []byte
	data = append(data, byte(len(names)))
	for _, n := range names {
		data = append(data, n...)
	}
	data = append(data, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
	data = append(data, make([]byte, 40)...)
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(data)))
	resp = append(resp, data...)
	info, err := ParseNBSTAT(resp)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "PC-COMPTA" || info.Domain != "BUREAU" || info.User != "MARIE" || !info.FileShare || info.MAC != "00:11:22:33:44:55" {
		t.Errorf("%+v", info)
	}
	if _, err := ParseNBSTAT([]byte{1, 2, 3}); err == nil {
		t.Error("réponse courte acceptée")
	}
}

func TestParseSNMPSysDescr(t *testing.T) {
	descr := "Linux nas 5.10.60-qnap #1 SMP x86_64"
	oid := []byte{0x06, 0x08, 0x2b, 6, 1, 2, 1, 1, 1, 0}
	vb := append(append([]byte{}, oid...), 0x04, byte(len(descr)))
	vb = append(vb, descr...)
	pkt := append([]byte{0x30, 0x40, 0x02, 0x01, 0x00, 0x04, 0x06}, "public"...)
	pkt = append(pkt, 0xa2, 0x30, 0x30, byte(len(vb)+2), 0x30, byte(len(vb)))
	pkt = append(pkt, vb...)
	got, err := ParseSNMPSysDescr(pkt)
	if err != nil || got != descr {
		t.Errorf("%q %v", got, err)
	}
}

func TestParseDNSTXTAndMDNS(t *testing.T) {
	// Réponse version.bind : question + un TXT « dnsmasq-2.90 ».
	q := []byte{0x41, 0x52, 0x85, 0x00, 0, 1, 0, 1, 0, 0, 0, 0}
	q = append(q, 7)
	q = append(q, "version"...)
	q = append(q, 4)
	q = append(q, "bind"...)
	q = append(q, 0, 0, 16, 0, 3)
	txt := "dnsmasq-2.90"
	q = append(q, 0xc0, 12, 0, 16, 0, 3, 0, 0, 0, 0, 0, byte(len(txt)+1), byte(len(txt)))
	q = append(q, txt...)
	if got, err := ParseDNSTXT(q); err != nil || got != txt {
		t.Errorf("%q %v", got, err)
	}

	// Réponse mDNS : deux PTR vers des types de services.
	m := []byte{0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0}
	m = append(m, encodeTestName("_services._dns-sd._udp.local")...)
	m = append(m, 0, 12, 0, 1, 0, 0, 0, 10)
	target := encodeTestName("_ipp._tcp.local")
	m = binary.BigEndian.AppendUint16(m, uint16(len(target)))
	m = append(m, target...)
	m = append(m, 0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 10) // nom compressé
	t2 := append([]byte{11}, "_googlecast"...)
	t2 = append(t2, 4)
	t2 = append(t2, "_tcp"...)
	t2 = append(t2, 0xc0, 35) // pointeur vers « local » (12 + 10 + 8 + 5)
	m = binary.BigEndian.AppendUint16(m, uint16(len(t2)))
	m = append(m, t2...)
	got := ParseMDNSPointers(m)
	if len(got) != 2 || got[0] != "_ipp._tcp.local" || got[1] != "_googlecast._tcp.local" {
		t.Errorf("%v", got)
	}
}

func encodeTestName(n string) []byte {
	var b []byte
	for _, l := range strings.Split(n, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func TestSSDPAndUPnP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>Freebox</friendlyName>
<manufacturer>Freebox SAS</manufacturer><modelName>Freebox Server</modelName><modelNumber>7</modelNumber></device></root>`)
	}))
	defer srv.Close()
	raw := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: " + srv.URL + "/desc.xml\r\nSERVER: Linux/4.19 UPnP/1.0 MiniUPnPd/2.2\r\nST: upnp:rootdevice\r\n\r\n"
	info, err := ParseSSDP([]byte(raw))
	if err != nil || info.Server != "Linux/4.19 UPnP/1.0 MiniUPnPd/2.2" || info.ST != "upnp:rootdevice" {
		t.Fatalf("%+v %v", info, err)
	}
	if err := FetchUPnPDescription(context.Background(), lo, info, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if info.FriendlyName != "Freebox" || info.Manufacturer != "Freebox SAS" || !strings.Contains(info.DeviceType, "InternetGateway") {
		t.Errorf("%+v", info)
	}
	other := &SSDPInfo{Location: "http://192.0.2.1/desc.xml"}
	if err := FetchUPnPDescription(context.Background(), lo, other, time.Second); err == nil {
		t.Error("description hébergée ailleurs suivie")
	}
}

// Faux serveur SMB : accepte SMB1 si v1, répond en SMB2 3.0.2 avec signature exigée.
func smbServer(t *testing.T, v1 bool) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var hdr [4]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint32(hdr[:]))
				io.ReadFull(c, msg)
				var resp []byte
				switch {
				case string(msg[:4]) == "\xffSMB" && v1:
					resp = append([]byte("\xffSMB\x72"), make([]byte, 40)...)
				case string(msg[:4]) == "\xffSMB":
					return // SMB1 refusé : connexion fermée
				default:
					resp = make([]byte, 64+8)
					copy(resp, "\xfeSMB")
					binary.LittleEndian.PutUint16(resp[64:], 65)
					binary.LittleEndian.PutUint16(resp[66:], 0x03)
					binary.LittleEndian.PutUint16(resp[68:], 0x0302)
				}
				out := binary.BigEndian.AppendUint32(nil, uint32(len(resp)))
				c.Write(append(out, resp...))
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func TestSMB(t *testing.T) {
	for _, v1 := range []bool{true, false} {
		port := smbServer(t, v1)
		info, err := SMB(context.Background(), netip.AddrPortFrom(lo, uint16(port)).String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if info.SMBv1 != v1 || info.Signing != "required" || info.Dialects[len(info.Dialects)-1] != "3.0.2" {
			t.Errorf("v1=%v : %+v", v1, info)
		}
	}
	if len(smb1Negotiate()) != 32+3+12 || len(smb2Negotiate()) != 64+36+8 {
		t.Errorf("tailles : %d %d", len(smb1Negotiate()), len(smb2Negotiate()))
	}
}
