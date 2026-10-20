package ctransport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// tlsClient performs the TLS 1.3 handshake. With a uTLS fingerprint it uses a
// utls.UClient; with "none" (or no fingerprint) it uses crypto/tls. ECH is
// read from ech-opts (notes/rev-transport.md §2.4: readECH/splitEarlyData and
// the ECH memo group around 0xb50940).
func (t *Transport) tlsClient(ctx context.Context, c net.Conn) (net.Conn, error) {
	cfg := t.buildTLSConfig()
	fp := firstNonEmpty(
		t.Settings.Str("client-fingerprint", "client_fingerprint", "fingerprint"),
		t.TLS.Str("client-fingerprint", "client_fingerprint", "fingerprint"),
	)
	id, shuffle, err := helloID(fp)
	if err != nil {
		return nil, err
	}
	if err := t.applyECH(cfg); err != nil {
		return nil, err
	}
	if id.Client == "" || id.Client == "none" {
		tc := utls.UClient(c, cfg, utls.HelloGolang)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return tc, nil
	}
	var uconn *utls.UConn
	if shuffle {
		// chrome: utlsIdToSpec(Chrome/133) then ShuffleChromeTLSExtensions
		// (notes/rev-round2-transport.md §B2-B3, call sites 0xb4e862/0xb4eda0).
		spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
		if err != nil {
			return nil, err
		}
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
		uconn = utls.UClient(c, cfg, utls.HelloCustom)
		if err := uconn.ApplyPreset(&spec); err != nil {
			return nil, fmt.Errorf("client-fingerprint %q: %w", fp, err)
		}
	} else {
		uconn = utls.UClient(c, cfg, id)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uconn, nil
}

func (t *Transport) buildTLSConfig() *utls.Config {
	cfg := &utls.Config{
		ServerName:         t.sni,
		InsecureSkipVerify: t.insecure(),
		NextProtos:         t.clientALPN(),
		MinVersion:         utls.VersionTLS13,
	}
	if v := firstNonEmpty(t.TLS.Str("pinned_cert_sha256", "pinnedCertSha256"), t.Settings.Str("pinned_cert_sha256")); v != "" {
		if want, err := decodeHexFingerprint(v); err == nil {
			cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errors.New("tls: the server sent no certificate")
				}
				sum := sha256.Sum256(raw[0])
				if subtle.ConstantTimeCompare(sum[:], want) != 1 {
					return fmt.Errorf("tls: the server's certificate is %x, not the pinned fingerprint: the server changed its certificate or something is in between", sum[:4])
				}
				return nil
			}
			cfg.InsecureSkipVerify = true
		}
	}
	return cfg
}

// applyECH reads ech-opts: enable, config (base64 ECHConfigList) and
// query-server-name. Errors follow the string table:
//   - ech-opts.enable %v is not true or false
//   - the ECH config (ech-opts.config) is not base64: paste the ECH config
//     list as the server or its DNS HTTPS record gives it
//   - ech-opts and reality-opts are both on: REALITY has no ECH ...
func (t *Transport) applyECH(cfg *utls.Config) error {
	ech := subOpt(t.Settings, "ech-opts", "ech_opts", "echSettings")
	if len(ech) == 0 {
		// outbound's reader puts the config in tlsSettings as ech_config/ech.
		if conf := firstNonEmpty(
			t.TLS.Str("ech_config", "ech-config", "echConfigList", "ech"),
			t.Settings.Str("ech_config", "ech-config", "echConfigList", "ech"),
		); conf != "" {
			if t.Security == "reality" {
				return errors.New("ech-opts and reality-opts are both on: REALITY has no ECH (its hello shows the borrowed site's name by design); remove one of them")
			}
			if t.Security != "tls" {
				return errors.New("ECH is for TLS, and this outbound is REALITY or has no TLS: remove the ECH config, or use security=tls")
			}
			return setECHConfig(cfg, conf)
		}
		return nil
	}
	if t.Security == "reality" {
		return errors.New("ech-opts and reality-opts are both on: REALITY has no ECH (its hello shows the borrowed site's name by design); remove one of them")
	}
	if t.Security != "tls" {
		return errors.New("ECH is for TLS, and this outbound is REALITY or has no TLS: remove the ECH config, or use security=tls")
	}
	if v, ok := ech["enable"]; ok {
		s := strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))
		if s != "true" && s != "false" {
			return fmt.Errorf("ech-opts.enable %v is not true or false", v)
		}
		if s == "false" {
			return nil
		}
	}
	conf := ech.Str("config", "configList", "config-list")
	if conf == "" {
		return nil
	}
	return setECHConfig(cfg, conf)
}

func setECHConfig(cfg *utls.Config, conf string) error {
	raw, err := base64.StdEncoding.DecodeString(conf)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(conf)
	}
	if err != nil {
		return errors.New("the ECH config (ech-opts.config) is not base64: paste the ECH config list as the server or its DNS HTTPS record gives it")
	}
	cfg.EncryptedClientHelloConfigList = raw
	return nil
}
