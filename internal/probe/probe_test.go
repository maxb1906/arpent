package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

var lo = netip.MustParseAddr("127.0.0.1")

func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return n
}

// bannerServer envoie banner à chaque connexion puis attend.
func bannerServer(t *testing.T, banner []byte) int {
	t.Helper()
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
			go func() {
				c.Write(banner)
				time.Sleep(500 * time.Millisecond)
				c.Close()
			}()
		}
	}()
	return portOf(t, l.Addr().String())
}

var fast = Options{Timeout: 2 * time.Second, BannerWait: 400 * time.Millisecond}

func TestBanners(t *testing.T) {
	mysql := append([]byte{0x4a, 0, 0, 0, 10}, []byte("8.0.36-0ubuntu0.22.04.1\x00\x08\x00\x00\x00")...)
	cases := []struct {
		banner             []byte
		name, product, ver string
	}{
		{[]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"), "ssh", "OpenSSH", "8.9p1"},
		{[]byte("220 (vsFTPd 3.0.5)\r\n"), "ftp", "vsFTPd", "3.0.5"},
		{[]byte("220 mail.example.org ESMTP Postfix (Ubuntu)\r\n"), "smtp", "Postfix", ""},
		{[]byte("+OK Dovecot ready.\r\n"), "pop3", "", ""},
		{[]byte("* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"), "imap", "", ""},
		{[]byte{0xff, 0xfd, 0x18, 0xff, 0xfd, 0x20}, "telnet", "", ""},
		{[]byte("RFB 003.008\n"), "vnc", "", "003.008"},
		{mysql, "mysql", "", "8.0.36-0ubuntu0.22.04.1"},
	}
	for _, c := range cases {
		port := bannerServer(t, c.banner)
		s := TCP(context.Background(), lo, port, fast)
		if s.Name != c.name || s.Product != c.product || s.Version != c.ver {
			t.Errorf("%q → %+v", c.banner, s)
		}
	}
}

func TestParseSSHBanner(t *testing.T) {
	i := ParseSSHBanner("SSH-1.99-Cisco-1.25")
	if i.Protocol != "1.99" || i.Product != "Cisco" || i.Version != "1.25" {
		t.Errorf("%+v", i)
	}
	i = ParseSSHBanner("SSH-2.0-dropbear_2022.83")
	if i.Product != "dropbear" || i.Version != "2022.83" {
		t.Errorf("%+v", i)
	}
}

const page = `<!DOCTYPE html><html><head><title>
  QNAP   Turbo NAS </title><link rel="shortcut icon" href="/static/fav.png"></head><body>Login</body></html>`

func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("User-Agent") != UserAgent {
			w.WriteHeader(400)
		}
		w.Header().Set("Server", "nginx/1.18.0 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/8.1")
		io.WriteString(w, page)
	})
	mux.HandleFunc("/static/fav.png", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("\x89PNG fake icon"))
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Router Admin"`)
		w.WriteHeader(401)
	})
	return mux
}

func TestHTTP(t *testing.T) {
	srv := httptest.NewServer(handler())
	defer srv.Close()
	s := TCP(context.Background(), lo, portOf(t, srv.Listener.Addr().String()), fast)
	if s.Name != "http" || s.HTTP == nil {
		t.Fatalf("%+v", s)
	}
	h := s.HTTP
	if h.Status != 200 || h.Title != "QNAP Turbo NAS" || h.Server != "nginx/1.18.0 (Ubuntu)" || h.PoweredBy != "PHP/8.1" {
		t.Errorf("%+v", h)
	}
	if !h.HasFavicon || h.FaviconHash != FaviconHash([]byte("\x89PNG fake icon")) {
		t.Errorf("favicon : %+v", h)
	}
	if s.Product != "nginx" || s.Version != "1.18.0" {
		t.Errorf("produit : %q %q", s.Product, s.Version)
	}
}

func TestHTTPSAndCert(t *testing.T) {
	srv := httptest.NewTLSServer(handler())
	defer srv.Close()
	port := portOf(t, srv.Listener.Addr().String())
	s := TCP(context.Background(), lo, port, fast)
	if s.Name != "https" || s.TLS == nil || s.HTTP == nil || s.HTTP.Title != "QNAP Turbo NAS" {
		t.Fatalf("%+v", s)
	}
	cert := srv.Certificate()
	if s.TLS.NotAfter.Unix() != cert.NotAfter.Unix() || s.TLS.Version == "" || s.TLS.SHA256 == "" {
		t.Errorf("TLS : %+v", s.TLS)
	}
	if s.TLS.Subject == "" && s.TLS.Issuer == "" {
		t.Errorf("sujet/émetteur vides : %+v", s.TLS)
	}
}

func TestTLSOnly(t *testing.T) {
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	cfg := &tls.Config{Certificates: cert.TLS.Certificates}
	cert.Close()
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); time.Sleep(200 * time.Millisecond); c.Close() }()
		}
	}()
	s := TCP(context.Background(), lo, portOf(t, l.Addr().String()), fast)
	if s.Name != "tls" || s.TLS == nil {
		t.Errorf("%+v", s)
	}
}

func TestRealmAndTitleHelpers(t *testing.T) {
	if r := realm(`Basic realm="Router Admin", charset="UTF-8"`); r != "Router Admin" {
		t.Errorf("realm = %q", r)
	}
	if r := realm(`Digest realm=cam, nonce="x"`); r != "cam" {
		t.Errorf("realm = %q", r)
	}
	title, _ := parseHTML([]byte("<title>R\xe9seau</title>"))
	if title != "Réseau" {
		t.Errorf("titre Latin-1 : %q", title)
	}
	if strings.ContainsAny(cleanBanner([]byte("a\x00b\x1bc")), "\x00\x1b") {
		t.Error("caractères de contrôle conservés")
	}
}

func TestMurmur3(t *testing.T) {
	cases := map[string]uint32{"": 0, "hello": 0x248bfa47, "Hello, world!": 0xc0363e43, "abc": 0xb3dd93fa}
	for in, want := range cases {
		if got := murmur3([]byte(in), 0); got != want {
			t.Errorf("murmur3(%q) = %#x, attendu %#x", in, got, want)
		}
	}
}

func TestAll(t *testing.T) {
	p1 := bannerServer(t, []byte("SSH-2.0-OpenSSH_9.6\r\n"))
	srv := httptest.NewServer(handler())
	defer srv.Close()
	targets := []Target{{lo, p1}, {lo, portOf(t, srv.Listener.Addr().String())}}
	res := All(context.Background(), targets, 4, 0, fast, nil)
	if res[0].Name != "ssh" || res[1].Name != "http" {
		t.Errorf("%+v", res)
	}
}
