package probe

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// HTTPInfo résume la réponse à « GET / ».
type HTTPInfo struct {
	Status      int    `json:"status"`
	Title       string `json:"title,omitempty"`
	Server      string `json:"server,omitempty"`
	PoweredBy   string `json:"powered_by,omitempty"`
	Location    string `json:"location,omitempty"`   // redirection
	AuthRealm   string `json:"auth_realm,omitempty"` // WWW-Authenticate realm
	ContentType string `json:"content_type,omitempty"`
	// FaviconHash est le hachage MurmurHash3 du favicon encodé en base64, au
	// format utilisé par Shodan (http.favicon.hash), pour reconnaître les
	// interfaces connues.
	FaviconHash int32 `json:"favicon_hash,omitempty"`
	HasFavicon  bool  `json:"has_favicon,omitempty"`
	// BodySample garde le début de la page pour les signatures (non exporté en JSON).
	BodySample string `json:"-"`
}

// UserAgent identifie honnêtement l'outil auprès des serveurs audités.
const UserAgent = "Arpent (network audit; +https://github.com/maxb1906/arpent)"

func httpClient(ip netip.Addr, port int, timeout time.Duration) *http.Client {
	addr := netip.AddrPortFrom(ip, uint16(port)).String()
	d := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		DialContext:            func(ctx context.Context, _, _ string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) },
		TLSClientConfig:        legacyConfig(),
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       2 * timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func baseURL(ip netip.Addr, port int, useTLS bool) string {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return scheme + "://" + netip.AddrPortFrom(ip, uint16(port)).String()
}

// HTTPGet envoie « GET / » et analyse la réponse, sans suivre les redirections.
func HTTPGet(ctx context.Context, ip netip.Addr, port int, useTLS bool, opt Options) (*HTTPInfo, error) {
	opt.defaults()
	client := httpClient(ip, port, opt.Timeout)
	defer client.CloseIdleConnections()
	base := baseURL(ip, port, useTLS)
	body, resp, err := get(ctx, client, base+"/", opt.MaxBodyBytes)
	if err != nil {
		return nil, err
	}
	h := &HTTPInfo{
		Status:      resp.StatusCode,
		Server:      cleanBanner([]byte(resp.Header.Get("Server"))),
		PoweredBy:   cleanBanner([]byte(resp.Header.Get("X-Powered-By"))),
		Location:    cleanBanner([]byte(resp.Header.Get("Location"))),
		AuthRealm:   realm(resp.Header.Get("WWW-Authenticate")),
		ContentType: resp.Header.Get("Content-Type"),
	}
	title, icon := parseHTML(body)
	h.Title = title
	n := len(body)
	if n > 4096 {
		n = 4096
	}
	h.BodySample = toUTF8(body[:n])

	if !opt.SkipFavicon {
		iconURL := base + "/favicon.ico"
		if icon != "" {
			if u, err := url.Parse(icon); err == nil {
				if b, err := url.Parse(base + "/"); err == nil {
					ref := b.ResolveReference(u)
					// On ne suit que les icônes du même hôte.
					if ref.Host == b.Host && strings.HasPrefix(ref.Scheme, "http") {
						iconURL = ref.String()
					}
				}
			}
		}
		if data, r, err := get(ctx, client, iconURL, 512<<10); err == nil && r.StatusCode == 200 && len(data) > 0 && !looksLikeHTML(data) {
			h.HasFavicon = true
			h.FaviconHash = FaviconHash(data)
		}
	}
	return h, nil
}

func get(ctx context.Context, c *http.Client, u string, max int64) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/html,*/*;q=0.8")
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, max))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && len(body) == 0 {
		return nil, resp, nil
	}
	return body, resp, nil
}

func looksLikeHTML(b []byte) bool {
	h := bytes.ToLower(bytes.TrimSpace(b[:min(len(b), 64)]))
	return bytes.HasPrefix(h, []byte("<!doctype")) || bytes.HasPrefix(h, []byte("<html"))
}

func realm(h string) string {
	i := strings.Index(strings.ToLower(h), "realm=")
	if i < 0 {
		return ""
	}
	v := h[i+6:]
	if strings.HasPrefix(v, `"`) {
		v = v[1:]
		if j := strings.IndexByte(v, '"'); j >= 0 {
			v = v[:j]
		}
	} else if j := strings.IndexAny(v, ", "); j >= 0 {
		v = v[:j]
	}
	return cleanBanner([]byte(v))
}

// parseHTML renvoie le titre de la page et l'adresse de son icône éventuelle.
func parseHTML(body []byte) (title, icon string) {
	z := html.NewTokenizer(bytes.NewReader(body))
	inTitle := false
	for {
		switch z.Next() {
		case html.ErrorToken:
			return strings.TrimSpace(title), icon
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			switch string(name) {
			case "title":
				inTitle = title == ""
			case "link":
				var rel, href string
				for hasAttr {
					var k, v []byte
					k, v, hasAttr = z.TagAttr()
					switch string(k) {
					case "rel":
						rel = strings.ToLower(string(v))
					case "href":
						href = string(v)
					}
				}
				if icon == "" && href != "" && strings.Contains(rel, "icon") {
					icon = href
				}
			}
		case html.TextToken:
			if inTitle {
				title += toUTF8(z.Text())
			}
		case html.EndTagToken:
			if name, _ := z.TagName(); string(name) == "title" {
				inTitle = false
				t := strings.Join(strings.Fields(title), " ")
				if len(t) > 200 {
					t = t[:200]
				}
				title = t
			}
		}
	}
}

// toUTF8 traite un texte non UTF-8 comme du Latin-1 (fréquent sur les
// interfaces web d'équipements anciens).
func toUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// FaviconHash calcule le hachage « à la Shodan » : MurmurHash3 (32 bits,
// graine 0) du contenu encodé en base64 avec un saut de ligne tous les 76
// caractères et à la fin (comme base64.encodebytes de Python).
func FaviconHash(data []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	for len(enc) > 76 {
		sb.WriteString(enc[:76])
		sb.WriteByte('\n')
		enc = enc[76:]
	}
	sb.WriteString(enc)
	sb.WriteByte('\n')
	return int32(murmur3([]byte(sb.String()), 0))
}

// murmur3 : MurmurHash3 x86 32 bits.
func murmur3(data []byte, seed uint32) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := uint32(data[4*i]) | uint32(data[4*i+1])<<8 | uint32(data[4*i+2])<<16 | uint32(data[4*i+3])<<24
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
		h = h<<13 | h>>19
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[4*n:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// String rend un statut HTTP lisible (« 200 OK »).
func (h *HTTPInfo) StatusText() string {
	return strconv.Itoa(h.Status) + " " + http.StatusText(h.Status)
}
