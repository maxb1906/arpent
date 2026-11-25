package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// SMB interroge un serveur SMB (TCP 445) sans s'authentifier : une première
// connexion propose uniquement le dialecte SMB 1 « NT LM 0.12 » (accepté =
// SMBv1 actif), une seconde négocie SMB 2/3 (dialecte retenu, signature).
func SMB(ctx context.Context, addr string, timeout time.Duration) (*SMBInfo, error) {
	info := &SMBInfo{}
	if resp, err := smbExchange(ctx, addr, timeout, smb1Negotiate()); err == nil && len(resp) >= 9 &&
		string(resp[0:4]) == "\xffSMB" && resp[4] == 0x72 && binary.LittleEndian.Uint32(resp[5:9]) == 0 {
		info.SMBv1 = true
		info.Dialects = append(info.Dialects, "1")
	}
	resp, err := smbExchange(ctx, addr, timeout, smb2Negotiate())
	if err == nil && len(resp) >= 64+6 && string(resp[0:4]) == "\xfeSMB" {
		body := resp[64:]
		sec := binary.LittleEndian.Uint16(body[2:])
		if d := dialectName(binary.LittleEndian.Uint16(body[4:])); d != "" {
			info.Dialects = append(info.Dialects, d)
		}
		switch {
		case sec&0x02 != 0:
			info.Signing = "required"
		case sec&0x01 != 0:
			info.Signing = "enabled"
		}
	}
	if len(info.Dialects) == 0 {
		return nil, errors.New("pas de réponse SMB")
	}
	return info, nil
}

func dialectName(d uint16) string {
	switch d {
	case 0x0202:
		return "2.0.2"
	case 0x0210:
		return "2.1"
	case 0x0300:
		return "3.0"
	case 0x0302:
		return "3.0.2"
	case 0x0311:
		return "3.1.1"
	}
	return ""
}

// smbExchange envoie un message encapsulé NetBIOS et lit la réponse.
func smbExchange(ctx context.Context, addr string, timeout time.Duration, msg []byte) ([]byte, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	frame := make([]byte, 4, 4+len(msg))
	binary.BigEndian.PutUint32(frame, uint32(len(msg))) // octet 0 = 0 (message de session)
	if _, err := c.Write(append(frame, msg...)); err != nil {
		return nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]) & 0x00ffffff)
	if n <= 0 || n > 64<<10 {
		return nil, errors.New("trame SMB invalide")
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// smb1Negotiate : SMB_COM_NEGOTIATE ne proposant que « NT LM 0.12 ».
func smb1Negotiate() []byte {
	h := make([]byte, 32)
	copy(h, "\xffSMB")
	h[4] = 0x72                                   // SMB_COM_NEGOTIATE
	h[9] = 0x18                                   // flags : noms insensibles à la casse
	binary.LittleEndian.PutUint16(h[10:], 0xc801) // flags2 : unicode, statuts NT, noms longs
	binary.LittleEndian.PutUint16(h[26:], 0xfeff) // PID
	dialect := append([]byte{0x02}, "NT LM 0.12\x00"...)
	body := []byte{0x00} // WordCount
	body = binary.LittleEndian.AppendUint16(body, uint16(len(dialect)))
	return append(append(h, body...), dialect...)
}

// smb2Negotiate : NEGOTIATE SMB2 proposant 2.0.2 à 3.0.2 (3.1.1 exigerait
// des contextes de négociation supplémentaires).
func smb2Negotiate() []byte {
	h := make([]byte, 64)
	copy(h, "\xfeSMB")
	binary.LittleEndian.PutUint16(h[4:], 64) // StructureSize
	binary.LittleEndian.PutUint16(h[14:], 1) // CreditRequest
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302}
	b := make([]byte, 36)
	binary.LittleEndian.PutUint16(b[0:], 36)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(b[4:], 1) // signature activée côté client
	copy(b[12:28], "arpent-netaudit!")      // ClientGuid
	for _, d := range dialects {
		b = binary.LittleEndian.AppendUint16(b, d)
	}
	return append(h, b...)
}
