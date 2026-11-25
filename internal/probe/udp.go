package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

// NetBIOSInfo : table des noms renvoyée par une requête NBSTAT.
type NetBIOSInfo struct {
	Name      string   `json:"name,omitempty"`   // nom de la machine (<00> unique)
	Domain    string   `json:"domain,omitempty"` // groupe de travail ou domaine (<00> groupe)
	User      string   `json:"user,omitempty"`   // utilisateur connecté (<03>), si annoncé
	FileShare bool     `json:"file_share"`       // service serveur <20> présent
	MAC       string   `json:"mac,omitempty"`    // adresse annoncée dans les statistiques
	Names     []string `json:"names,omitempty"`  // tous les noms « NOM<xx> »
}

// ParseNBSTAT décode une réponse NBSTAT (RFC 1002, § 4.2.18).
func ParseNBSTAT(b []byte) (*NetBIOSInfo, error) {
	if len(b) < 57 {
		return nil, errors.New("réponse NBSTAT trop courte")
	}
	// En-tête (12) + nom de la question (34 : longueur, 32 octets, 0) + type,
	// classe, TTL (8) + longueur des données (2) = 56, puis le nombre de noms.
	off := 12
	for off < len(b) && b[off] != 0 {
		off += int(b[off]) + 1
	}
	off++                // 0 final du nom
	off += 2 + 2 + 4 + 2 // type, classe, TTL, longueur
	if off >= len(b) {
		return nil, errors.New("réponse NBSTAT tronquée")
	}
	n := int(b[off])
	off++
	info := &NetBIOSInfo{}
	for i := 0; i < n && off+18 <= len(b); i++ {
		name := strings.TrimRight(string(b[off:off+15]), " \x00")
		suffix := b[off+15]
		flags := binary.BigEndian.Uint16(b[off+16:])
		group := flags&0x8000 != 0
		off += 18
		info.Names = append(info.Names, name+"<"+hex2(suffix)+">")
		switch {
		case suffix == 0x00 && !group && info.Name == "":
			info.Name = name
		case suffix == 0x00 && group && info.Domain == "":
			info.Domain = name
		case suffix == 0x03 && !group && name != info.Name && info.User == "":
			info.User = name
		case suffix == 0x20:
			info.FileShare = true
		}
	}
	if off+6 <= len(b) {
		mac := net.HardwareAddr(b[off : off+6])
		if !bytes.Equal(mac, make([]byte, 6)) {
			info.MAC = mac.String()
		}
	}
	if info.Name == "" && len(info.Names) == 0 {
		return nil, errors.New("aucun nom NetBIOS")
	}
	return info, nil
}

func hex2(b byte) string {
	const h = "0123456789ABCDEF"
	return string([]byte{h[b>>4], h[b&0x0f]})
}

// ParseSNMPSysDescr extrait la première chaîne (OCTET STRING) des données
// d'une réponse SNMP GetResponse : sysDescr.0.
func ParseSNMPSysDescr(b []byte) (string, error) {
	// Parcours BER simplifié : on cherche la séquence de varbinds et la
	// valeur qui suit l'OID 1.3.6.1.2.1.1.1.0.
	oid := []byte{0x06, 0x08, 0x2b, 6, 1, 2, 1, 1, 1, 0}
	i := bytes.Index(b, oid)
	if i < 0 {
		return "", errors.New("sysDescr absent")
	}
	v := b[i+len(oid):]
	if len(v) < 2 || v[0] != 0x04 {
		return "", errors.New("sysDescr : type inattendu")
	}
	l, n := berLen(v[1:])
	if n == 0 || 1+n+l > len(v) {
		return "", errors.New("sysDescr : longueur invalide")
	}
	return cleanBanner(v[1+n : 1+n+l]), nil
}

func berLen(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	if b[0] < 0x80 {
		return int(b[0]), 1
	}
	k := int(b[0] & 0x7f)
	if k == 0 || k > 3 || len(b) < 1+k {
		return 0, 0
	}
	l := 0
	for _, x := range b[1 : 1+k] {
		l = l<<8 | int(x)
	}
	return l, 1 + k
}

// ParseDNSTXT renvoie la première chaîne TXT d'une réponse DNS (version.bind).
func ParseDNSTXT(b []byte) (string, error) {
	if len(b) < 12 || b[2]&0x80 == 0 {
		return "", errors.New("pas une réponse DNS")
	}
	qd, an := binary.BigEndian.Uint16(b[4:]), binary.BigEndian.Uint16(b[6:])
	off := 12
	for i := 0; i < int(qd); i++ {
		off = skipName(b, off) + 4
	}
	for i := 0; i < int(an) && off < len(b); i++ {
		off = skipName(b, off)
		if off+10 > len(b) {
			break
		}
		typ := binary.BigEndian.Uint16(b[off:])
		rdl := int(binary.BigEndian.Uint16(b[off+8:]))
		off += 10
		if off+rdl > len(b) {
			break
		}
		if typ == 16 && rdl > 1 {
			l := int(b[off])
			if 1+l <= rdl {
				return cleanBanner(b[off+1 : off+1+l]), nil
			}
		}
		off += rdl
	}
	return "", errors.New("pas de TXT")
}

func skipName(b []byte, off int) int {
	for off < len(b) {
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1
		case l&0xc0 == 0xc0:
			return off + 2
		default:
			off += l + 1
		}
	}
	return off
}

// readName lit un nom DNS (avec compression) à partir de off.
func readName(b []byte, off int) (string, int) {
	var labels []string
	end := -1
	for jumps := 0; off < len(b) && jumps < 16; {
		l := int(b[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return strings.Join(labels, "."), len(b)
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			jumps++
		default:
			if off+1+l > len(b) {
				return strings.Join(labels, "."), len(b)
			}
			labels = append(labels, string(b[off+1:off+1+l]))
			off += l + 1
		}
	}
	return strings.Join(labels, "."), len(b)
}

// ParseMDNSPointers renvoie les cibles des enregistrements PTR d'une réponse
// mDNS/DNS (types de services, ou nom d'hôte pour une requête inverse).
func ParseMDNSPointers(b []byte) []string {
	if len(b) < 12 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(b[4:]))
	rr := int(binary.BigEndian.Uint16(b[6:])) + int(binary.BigEndian.Uint16(b[8:])) + int(binary.BigEndian.Uint16(b[10:]))
	off := 12
	for i := 0; i < qd; i++ {
		off = skipName(b, off) + 4
	}
	var out []string
	seen := map[string]bool{}
	for i := 0; i < rr && off < len(b); i++ {
		off = skipName(b, off)
		if off+10 > len(b) {
			break
		}
		typ := binary.BigEndian.Uint16(b[off:])
		rdl := int(binary.BigEndian.Uint16(b[off+8:]))
		off += 10
		if off+rdl > len(b) {
			break
		}
		if typ == 12 {
			if name, _ := readName(b, off); name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
		off += rdl
	}
	return out
}

// MDNSReverseName demande à l'appareil son nom (.local) par une requête mDNS
// unicast inverse (PTR x.x.x.x.in-addr.arpa) sur le port 5353.
func MDNSReverseName(ctx context.Context, ip netip.Addr, timeout time.Duration) string {
	if !ip.Is4() {
		return ""
	}
	a := ip.As4()
	name := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", a[3], a[2], a[1], a[0])
	q := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(q[4:], 1)
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 12, 0x80, 1) // PTR, classe IN avec bit « réponse unicast »
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "udp", netip.AddrPortFrom(ip, 5353).String())
	if err != nil {
		return ""
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(q); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return ""
	}
	for _, p := range ParseMDNSPointers(buf[:n]) {
		return strings.TrimSuffix(p, ".")
	}
	return ""
}

// SSDPInfo : réponse SSDP et description UPnP de l'appareil.
type SSDPInfo struct {
	Server       string `json:"server,omitempty"`
	Location     string `json:"location,omitempty"`
	ST           string `json:"st,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	ModelName    string `json:"model_name,omitempty"`
	ModelNumber  string `json:"model_number,omitempty"`
	DeviceType   string `json:"device_type,omitempty"`
}

// ParseSSDP lit les en-têtes d'une réponse à M-SEARCH.
func ParseSSDP(b []byte) (*SSDPInfo, error) {
	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(b)))
	line, err := r.ReadLine()
	if err != nil || !strings.HasPrefix(line, "HTTP/1.") {
		return nil, errors.New("pas une réponse SSDP")
	}
	h, _ := r.ReadMIMEHeader()
	return &SSDPInfo{Server: cleanBanner([]byte(h.Get("Server"))), Location: h.Get("Location"), ST: h.Get("St")}, nil
}

// FetchUPnPDescription lit la description XML annoncée par l'appareil
// (uniquement si elle est hébergée par l'appareil lui-même).
func FetchUPnPDescription(ctx context.Context, ip netip.Addr, info *SSDPInfo, timeout time.Duration) error {
	u, err := url.Parse(info.Location)
	if err != nil || u.Scheme != "http" {
		return errors.New("LOCATION invalide")
	}
	if h := u.Hostname(); h != ip.String() {
		return errors.New("description hébergée ailleurs")
	}
	c := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var doc struct {
		Device struct {
			DeviceType   string `xml:"deviceType"`
			FriendlyName string `xml:"friendlyName"`
			Manufacturer string `xml:"manufacturer"`
			ModelName    string `xml:"modelName"`
			ModelNumber  string `xml:"modelNumber"`
		} `xml:"device"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&doc); err != nil {
		return err
	}
	d := doc.Device
	info.DeviceType, info.FriendlyName = cleanBanner([]byte(d.DeviceType)), cleanBanner([]byte(d.FriendlyName))
	info.Manufacturer, info.ModelName, info.ModelNumber = cleanBanner([]byte(d.Manufacturer)), cleanBanner([]byte(d.ModelName)), cleanBanner([]byte(d.ModelNumber))
	return nil
}
