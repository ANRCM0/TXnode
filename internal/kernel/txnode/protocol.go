package txnode

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/anytls"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/httpproxy"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/mieru"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/naive"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/shadowsocks"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/snell"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/socks5"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/trojan"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/vless"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/vmess"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/xudp"
	"github.com/ANRCM0/TX-Node/internal/dataplane/transport"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
)

// coreUsers converts panel users. Speed and device ceilings are NOT carried
// here: the kernel applies them through Tracker.SetUserLimit / the device gate,
// so the tracker stays the only owner of rate state.
func coreUsers(users []model.UserSpec) []core.User {
	out := make([]core.User, 0, len(users))
	for _, u := range users {
		out = append(out, core.User{ID: u.ID, UUID: u.UUID})
	}
	return out
}

// buildHandler constructs the inbound protocol handler for one node.
func buildHandler(sp *spec, users []core.User, log *slog.Logger) (core.Handler, error) {
	muxPackets := func(conn net.Conn) core.PacketStream { return xudp.New(conn) }
	switch sp.Protocol {
	case "vless":
		return vless.NewHandler(vless.Options{
			Users:       users,
			Decryption:  sp.Decryption,
			Flow:        sp.Flow,
			AllowVision: sp.Flow != "",
			Logger:      log,
			MuxPackets:  muxPackets,
		})
	case "vmess":
		return vmess.NewHandler(vmess.Options{Users: users, Cipher: sp.Cipher, Logger: log, MuxPackets: muxPackets})
	case "trojan":
		return trojan.NewHandler(trojan.Options{Users: users})
	case "shadowsocks":
		if sp.Cipher == "" {
			return nil, errors.New("shadowsocks: cipher is required")
		}
		return shadowsocks.New(shadowsocks.Options{
			Users:     users,
			Cipher:    sp.Cipher,
			ServerKey: sp.ServerKey,
			UDP:       true,
		})
	case "socks5":
		return socks5.NewHandler(socks5.Options{Users: users, NoAuth: len(users) == 0, UDP: true})
	case "httpproxy":
		return httpproxy.NewHandler(httpproxy.Options{Users: users, NoAuth: len(users) == 0})
	case "anytls":
		return anytls.NewHandler(anytls.Options{Users: users, PaddingScheme: sp.PaddingScheme})
	case "naive":
		return naive.NewHandler(naive.Options{Users: users})
	case "mieru":
		return mieru.NewHandler(mieru.Options{
			AllowEmptyUsers: true,
			Users:           users,
			Transport:       sp.MieruTransport,
			TrafficPattern:  sp.MieruTrafficPattern,
			HintRequired:    sp.MieruHintRequired,
			Logger:          log,
		})
	case "snell":
		return snell.NewHandler(snell.Options{Users: users, Version: sp.Version, Logger: log})
	case "hysteria", "tuic":
		// QUIC-only: the datagram server owns the handshake and hands sessions
		// to core.Server.ServeSession through its Relay callback.
		return quicPlaceholder{}, nil
	default:
		return nil, fmt.Errorf("protocol %q is not supported", sp.Protocol)
	}
}

// security builds the TLS material the node will serve. TX-Node already
// normalised every certificate mode to PEM (kernel.TLSCert), and REALITY keys
// arrive through the panel's tls_settings, so no ACME or file handling happens
// here.
func security(cert kernel.TLSCert, sp *spec, log *slog.Logger) (*tls.Config, *transport.Reality, error) {
	if sp.TLS == 0 {
		return nil, nil, nil
	}
	if sp.TLS == 2 {
		if sp.Protocol == "naive" {
			return nil, nil, errors.New("naive clients do not speak REALITY; set the node security to TLS")
		}
		re, err := transport.NewReality(transport.RealityConfig{
			PrivateKey:  sp.RealityPrivateKey,
			ShortIDs:    sp.RealityShortIDs,
			Dest:        sp.RealityDest,
			ServerNames: sp.RealityServerNames,
			MaxTimeDiff: sp.RealityMaxTimeDiff,
			Logger:      log,
		})
		if err != nil {
			return nil, nil, err
		}
		return nil, re, nil
	}
	if !cert.HasCert() {
		return nil, nil, errors.New("no TLS certificate")
	}
	pair, err := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	}
	if len(sp.ALPN) > 0 {
		cfg.NextProtos = append([]string(nil), sp.ALPN...)
	}
	return cfg, nil, nil
}

// quicPlaceholder is the TCP-side handler of a QUIC-only protocol: any TCP
// connection to that port is closed.
type quicPlaceholder struct{}

func (quicPlaceholder) Handle(_ context.Context, conn net.Conn) (*core.Session, error) {
	_ = conn.Close()
	return nil, errors.New("this protocol is served over QUIC, not TCP")
}
