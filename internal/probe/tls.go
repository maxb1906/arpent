package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"strings"
	"time"
)

// TLSInfo décrit la connexion TLS et le certificat présenté.
type TLSInfo struct {
	Version    string    `json:"version"` // TLS 1.2, TLS 1.3…
	Cipher     string    `json:"cipher"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
	SHA256     string    `json:"sha256"` // empreinte du certificat
	KeyBits    int       `json:"key_bits,omitempty"`
	SigAlg     string    `json:"sig_alg,omitempty"`
}

// legacyConfig accepte les vieux équipements (TLS 1.0, suites anciennes) :
// on observe, on ne fait pas confiance — la vérification est volontairement
// désactivée et le certificat est analysé à part.
func legacyConfig() *tls.Config {
	var suites []uint16
	for _, s := range tls.CipherSuites() {
		suites = append(suites, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		suites = append(suites, s.ID)
	}
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // audit : on inspecte le certificat, on ne s'y fie pas
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       suites,
	}
}

// TLSHandshake établit une session TLS avec addr et décrit le certificat.
func TLSHandshake(ctx context.Context, addr string, timeout time.Duration) (*TLSInfo, error) {
	d := &net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(c, legacyConfig())
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	st := tc.ConnectionState()
	info := &TLSInfo{Version: tls.VersionName(st.Version), Cipher: tls.CipherSuiteName(st.CipherSuite)}
	if len(st.PeerCertificates) > 0 {
		describeCert(info, st.PeerCertificates[0])
	}
	return info, nil
}

func describeCert(info *TLSInfo, cert *x509.Certificate) {
	info.Subject = nameOf(cert.Subject.CommonName, cert.Subject.Organization)
	info.Issuer = nameOf(cert.Issuer.CommonName, cert.Issuer.Organization)
	info.DNSNames = cert.DNSNames
	info.NotBefore, info.NotAfter = cert.NotBefore.UTC(), cert.NotAfter.UTC()
	sum := sha256.Sum256(cert.Raw)
	info.SHA256 = hex.EncodeToString(sum[:])
	info.SigAlg = cert.SignatureAlgorithm.String()
	info.KeyBits = keyBits(cert)
	info.SelfSigned = bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil
	if !info.SelfSigned && bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		info.SelfSigned = true // signature non vérifiable (algorithme ancien) mais émetteur = sujet
	}
}

func nameOf(cn string, org []string) string {
	if cn != "" {
		return cn
	}
	return strings.Join(org, ", ")
}
