// Package probe identifie le service qui écoute sur un port ouvert : lecture
// de la bannière des services qui parlent en premier (SSH, FTP, SMTP, POP3,
// IMAP, Telnet, MySQL, VNC…), puis poignée de main TLS et requête HTTP pour
// les autres. Aucune authentification n'est tentée.
package probe

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

// Service décrit ce qui a été identifié sur un port.
type Service struct {
	Name    string    `json:"name,omitempty"`    // ssh, http, https, ftp, smtp…
	Product string    `json:"product,omitempty"` // OpenSSH, nginx, vsftpd…
	Version string    `json:"version,omitempty"`
	Banner  string    `json:"banner,omitempty"` // bannière brute, nettoyée
	TLS     *TLSInfo  `json:"tls,omitempty"`
	HTTP    *HTTPInfo `json:"http,omitempty"`
	SSH     *SSHInfo  `json:"ssh,omitempty"`
	SMB     *SMBInfo  `json:"smb,omitempty"`
}

// SMBInfo décrit un serveur SMB (rempli par la sonde SMB).
type SMBInfo struct {
	SMBv1    bool     `json:"smbv1"`              // accepte encore SMB 1
	Dialects []string `json:"dialects,omitempty"` // ex. 2.1, 3.1.1
	Signing  string   `json:"signing,omitempty"`  // required, enabled
}

// Options règle les sondes.
type Options struct {
	Timeout      time.Duration // délai de connexion et de lecture (défaut 3 s)
	BannerWait   time.Duration // attente d'une bannière spontanée (défaut 1,5 s)
	SkipFavicon  bool
	MaxBodyBytes int64 // taille lue d'une page HTTP (défaut 256 Kio)
}

func (o *Options) defaults() {
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.BannerWait <= 0 {
		o.BannerWait = 1500 * time.Millisecond
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = 256 << 10
	}
}

// tlsFirstPorts : ports où l'on tente TLS avant HTTP en clair.
var tlsFirstPorts = map[int]bool{443: true, 465: true, 636: true, 993: true, 995: true, 990: true,
	1443: true, 4443: true, 5001: true, 5986: true, 6443: true, 7443: true, 8006: true, 8443: true,
	8883: true, 9443: true, 10443: true}

// TCP sonde un port TCP ouvert.
func TCP(ctx context.Context, ip netip.Addr, port int, opt Options) Service {
	opt.defaults()
	addr := netip.AddrPortFrom(ip, uint16(port)).String()

	// 1. Bannière spontanée.
	if raw := readBanner(ctx, addr, opt); len(raw) > 0 {
		return classifyBanner(raw)
	}

	// 2. Pas de bannière : TLS puis HTTP (ou l'inverse selon le port).
	tryTLS := func() (Service, bool) {
		info, err := TLSHandshake(ctx, addr, opt.Timeout)
		if err != nil {
			return Service{}, false
		}
		s := Service{Name: "tls", TLS: info}
		if h, err := HTTPGet(ctx, ip, port, true, opt); err == nil {
			s.Name, s.HTTP = "https", h
			s.Product, s.Version = splitProduct(h.Server)
		}
		return s, true
	}
	tryHTTP := func() (Service, bool) {
		h, err := HTTPGet(ctx, ip, port, false, opt)
		if err != nil {
			return Service{}, false
		}
		// « 400 : requête HTTP envoyée à un port HTTPS » (nginx, Go, Jetty…) :
		// le port parle en réalité TLS.
		if h.Status == 400 {
			if s, ok := tryTLS(); ok {
				return s, true
			}
		}
		s := Service{Name: "http", HTTP: h}
		s.Product, s.Version = splitProduct(h.Server)
		return s, true
	}
	order := []func() (Service, bool){tryHTTP, tryTLS}
	if tlsFirstPorts[port] {
		order = []func() (Service, bool){tryTLS, tryHTTP}
	}
	for _, f := range order {
		if ctx.Err() != nil {
			break
		}
		if s, ok := f(); ok {
			return s
		}
	}
	return Service{}
}

// readBanner se connecte et lit ce que le serveur envoie spontanément.
func readBanner(ctx context.Context, addr string, opt Options) []byte {
	d := net.Dialer{Timeout: opt.Timeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(opt.BannerWait))
	buf := make([]byte, 2048)
	n, _ := c.Read(buf)
	if n > 0 && n < len(buf) && !bytes.Contains(buf[:n], []byte("\n")) && buf[0] != 0xff {
		// Bannière coupée : on laisse une courte chance à la suite.
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		m, _ := c.Read(buf[n:])
		n += m
	}
	return buf[:n]
}

// classifyBanner reconnaît les services qui parlent en premier.
func classifyBanner(raw []byte) Service {
	s := Service{Banner: cleanBanner(raw)}
	text := string(raw)
	first := strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	up := strings.ToUpper(first)
	switch {
	case strings.HasPrefix(text, "SSH-"):
		s.Name = "ssh"
		s.SSH = ParseSSHBanner(first)
		s.Product, s.Version = s.SSH.Product, s.SSH.Version
	case raw[0] == 0xff && len(raw) > 1 && raw[1] >= 0xfb: // IAC WILL/WONT/DO/DONT
		s.Name = "telnet"
	case strings.HasPrefix(text, "RFB "):
		s.Name = "vnc"
		s.Version = strings.TrimPrefix(first, "RFB ")
	case strings.HasPrefix(text, "+OK"):
		s.Name = "pop3"
	case strings.HasPrefix(text, "* OK"):
		s.Name = "imap"
	case strings.HasPrefix(up, "220"):
		switch {
		case strings.Contains(up, "SMTP") || strings.Contains(up, "MAIL") || strings.Contains(up, "POSTFIX") || strings.Contains(up, "EXIM"):
			s.Name = "smtp"
		default:
			s.Name = "ftp"
		}
		s.Product, s.Version = productFrom220(first)
	case isMySQLHandshake(raw):
		s.Name = "mysql"
		s.Version = mysqlVersion(raw)
		s.Banner = "MySQL " + s.Version
	case strings.HasPrefix(text, "HTTP/"):
		s.Name = "http"
	}
	return s
}

// productFrom220 extrait un produit connu d'une bannière « 220 … ».
func productFrom220(line string) (string, string) {
	for _, p := range []string{"vsFTPd", "ProFTPD", "Pure-FTPd", "FileZilla Server", "Microsoft FTP Service",
		"Postfix", "Exim", "Microsoft ESMTP MAIL Service", "Sendmail", "OpenSMTPD"} {
		i := strings.Index(strings.ToLower(line), strings.ToLower(p))
		if i < 0 {
			continue
		}
		rest := strings.TrimLeft(line[i+len(p):], " /")
		ver := ""
		if f := strings.Fields(rest); len(f) > 0 && len(f[0]) > 0 && (f[0][0] >= '0' && f[0][0] <= '9') {
			ver = strings.Trim(f[0], "()[],")
		}
		return p, ver
	}
	return "", ""
}

func isMySQLHandshake(b []byte) bool {
	// Paquet : longueur (3 octets), séquence 0, protocole 10, version\0
	if len(b) < 10 || b[3] != 0 || b[4] != 10 {
		return false
	}
	l := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
	return l > 0 && l <= len(b)-4+64 && bytes.IndexByte(b[5:], 0) > 0
}

func mysqlVersion(b []byte) string {
	end := bytes.IndexByte(b[5:], 0)
	return cleanBanner(b[5 : 5+end])
}

// cleanBanner rend une bannière affichable : UTF-8 valide, sans caractères
// de contrôle, limitée à 512 caractères.
func cleanBanner(raw []byte) string {
	var sb strings.Builder
	for len(raw) > 0 && sb.Len() < 512 {
		r, size := utf8.DecodeRune(raw)
		raw = raw[size:]
		switch {
		case r == '\r':
		case r == '\n' || r == '\t':
			sb.WriteRune(r)
		case r == utf8.RuneError && size == 1, r < 0x20, r == 0x7f:
			sb.WriteRune('·')
		default:
			sb.WriteRune(r)
		}
	}
	return strings.TrimSpace(sb.String())
}

// splitProduct sépare « nginx/1.18.0 (Ubuntu) » en ("nginx", "1.18.0").
func splitProduct(server string) (string, string) {
	f := strings.Fields(server)
	if len(f) == 0 {
		return "", ""
	}
	name, ver, _ := strings.Cut(f[0], "/")
	return name, ver
}
