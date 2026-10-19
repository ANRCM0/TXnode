package transport

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// serverTLSConfig prepares the TLS 1.3 server configuration for TLS == 1:
// certificate from the node (certs.Manager) or a self-signed fallback, plus
// the ALPN decision and the strict_alpn gate.
//
// Evidence: REPORT.md §7.1 (ALPN), §7.2 (TLS 1.3), notes/rev-transport.md
// §1.2; the self-signed warning line is the one observed in REPORT.md §20.5:
// "using a self-signed certificate; clients must allow insecure connections".
func (i *Inbound) serverTLSConfig() (*tls.Config, error) {
	var cfg *tls.Config
	if i.TLSConfig != nil {
		cfg = i.TLSConfig.Clone()
	} else {
		cfg = &tls.Config{}
	}
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = alpnFor(i.Network, false, cfg.NextProtos)

	if len(cfg.Certificates) == 0 && cfg.GetCertificate == nil {
		name := firstNonEmpty(i.Host, serverNameOf(cfg), "localhost")
		cert, err := selfSigned(name)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
		sum := sha256.Sum256(cert.Certificate[0])
		i.logger().Warn("using a self-signed certificate; clients must allow insecure connections",
			"name", name, "sha256", fmt.Sprintf("%x", sum[:4]))
	}

	if i.StrictALPN {
		cfg = strictALPN(cfg, i.Network, i.logger())
	}
	return cfg, nil
}

// strictALPN rejects a ClientHello that offers none of the transport's ALPN
// protocols. The sample's strict_alpn key is validated by conf; the runtime
// effect is a failed handshake rather than a fallback (REPORT.md §4.2 lists
// strict_alpn among the keys, §7.1 fixes the protocol sets).
func strictALPN(cfg *tls.Config, network string, log interface {
	Warn(string, ...any)
}) *tls.Config {
	want := alpnFor(network, false, cfg.NextProtos)
	prev := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if prev != nil {
			next, err := prev(hello)
			if err != nil {
				return nil, err
			}
			if next != nil {
				cfg = next
			}
		}
		if len(hello.SupportedProtos) == 0 {
			return nil, fmt.Errorf("strict_alpn: the client offered no ALPN protocol; this node serves %v", want)
		}
		for _, got := range hello.SupportedProtos {
			for _, w := range want {
				if got == w {
					return cfg, nil
				}
			}
		}
		return nil, fmt.Errorf("strict_alpn: the client offered %v, this node serves %v", hello.SupportedProtos, want)
	}
	return cfg
}

func serverNameOf(cfg *tls.Config) string { return cfg.ServerName }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// selfSigned builds the throw-away certificate the node uses when no
// certificate is configured (REPORT.md §20.5: "using a self-signed
// certificate; clients must allow insecure connections name=test.local
// sha256=0010093c...").
func selfSigned(name string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ecdsaCert is a P-256 companion certificate. REALITY's own certificate is
// ed25519 (NewReality calls ed25519.GenerateKey), but a client hello whose
// signature_algorithms list has no Ed25519 entry would otherwise fail the
// handshake; offering both lets crypto/tls pick the one the client accepts.
// The client never verifies the chain (REALITY has "no certificate check to
// switch off").
func ecdsaCert(name string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// ed25519Cert is the certificate NewReality self-signs to play the borrowed
// site (REPORT.md §7.5: crypto/ed25519.GenerateKey + crypto/x509.CreateCertificate
// + time.Add/AddDate inside NewReality).
func ed25519Cert(name string) (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
