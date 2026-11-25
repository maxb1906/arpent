package portscan

import "encoding/binary"

// UDPProbe est une sonde UDP ciblée : sans charge utile adaptée, un service
// UDP ne répond pas, donc on n'interroge que des services connus.
type UDPProbe struct {
	Port    int
	Service string
	Payload []byte
}

// DefaultUDPProbes : DNS, NetBIOS, SNMP, SSDP, mDNS (§ 5.2).
var DefaultUDPProbes = []UDPProbe{
	{53, "dns", dnsQuery(0x4152, "version.bind", 16, 3)}, // TXT CH version.bind
	{137, "netbios-ns", nbstatQuery()},
	{161, "snmp", snmpGetSysDescr("public")},
	{1900, "ssdp", []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")},
	{5353, "mdns", dnsQuery(0, "_services._dns-sd._udp.local", 12, 1)}, // PTR IN
}

// dnsQuery construit une requête DNS (qtype, qclass) pour name.
func dnsQuery(id uint16, name string, qtype, qclass uint16) []byte {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:], id)
	if id != 0 {
		binary.BigEndian.PutUint16(b[2:], 0x0100) // récursion souhaitée
	}
	binary.BigEndian.PutUint16(b[4:], 1) // une question
	b = append(b, encodeName(name)...)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, qclass)
	return b
}

func encodeName(name string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				out = append(out, byte(i-start))
				out = append(out, name[start:i]...)
			}
			start = i + 1
		}
	}
	return append(out, 0)
}

// nbstatQuery : requête NetBIOS « NBSTAT * » qui renvoie la table des noms.
func nbstatQuery() []byte {
	b := []byte{0x41, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20}
	// Nom « * » encodé NetBIOS (premier demi-octet + 'A'), complété par des zéros.
	name := make([]byte, 16)
	name[0] = '*'
	for _, c := range name {
		b = append(b, 'A'+c>>4, 'A'+c&0x0f)
	}
	b = append(b, 0x00, 0x00, 0x21, 0x00, 0x01) // fin du nom, type NBSTAT, classe IN
	return b
}

// snmpGetSysDescr : requête SNMPv1 GetRequest de sysDescr.0 avec la
// communauté donnée (encodage BER construit à la main).
func snmpGetSysDescr(community string) []byte {
	tlv := func(tag byte, content []byte) []byte {
		return append([]byte{tag, byte(len(content))}, content...)
	}
	oid := []byte{0x2b, 6, 1, 2, 1, 1, 1, 0} // 1.3.6.1.2.1.1.1.0
	varbind := tlv(0x30, append(tlv(0x06, oid), 0x05, 0x00))
	varbinds := tlv(0x30, varbind)
	pdu := tlv(0xa0, concat(tlv(0x02, []byte{0x41, 0x52}), tlv(0x02, []byte{0}), tlv(0x02, []byte{0}), varbinds))
	return tlv(0x30, concat(tlv(0x02, []byte{0}), tlv(0x04, []byte(community)), pdu))
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
