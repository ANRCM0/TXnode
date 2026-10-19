package txnode

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/hysteria"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/tuic"
	"github.com/ANRCM0/TX-Node/internal/dataplane/transport"
)

// bindResult is everything Start/Reload must own to run and later stop one
// node: the TCP listener (nil for QUIC-only protocols), the datagram socket
// (nil when the protocol has none) and the closers that are not covered by
// Server.Close.
type bindResult struct {
	ln      net.Listener
	pc      net.PacketConn
	closers []io.Closer
}

// closeDatagrams releases only the datagram side, keeping the TCP listener and
// the sessions it accepted (Reload needs this for QUIC-only ports).
func (b *bindResult) closeDatagrams() {
	if b == nil {
		return
	}
	if b.pc != nil {
		_ = b.pc.Close()
		b.pc = nil
	}
	for _, c := range b.closers {
		_ = c.Close()
	}
	b.closers = nil
}

func (b *bindResult) closeAll() {
	if b == nil {
		return
	}
	if b.ln != nil {
		_ = b.ln.Close()
	}
	if b.pc != nil {
		_ = b.pc.Close()
	}
	for _, c := range b.closers {
		_ = c.Close()
	}
}

// bind opens the node's sockets and wraps them with the node's transport.
// The protocol handler may be replaced by the transport (WS/gRPC/H2/XHTTP wrap
// it, ShadowTLS wraps it before that), so the effective handler is installed on
// the server here.
func bindNode(sp *spec, h core.Handler, users []core.User, tlsCfg *tls.Config,
	re *transport.Reality, srv *core.Server, rt RuntimeConfig, log *slog.Logger) (*bindResult, error) {

	res := &bindResult{}
	addr := sp.Addr()
	var err error
	if !quicOnly(sp.Protocol) {
		res.ln, err = listenReusePort(addr)
		if err != nil {
			return nil, fmt.Errorf("listen %s: %w", addr, err)
		}
	}

	network := strings.ToLower(strings.TrimSpace(sp.Network))
	if network == "" {
		network = "tcp"
	}
	handler := h

	// simple-obfs / obfs: the sample folds it into the "http" network.
	if sp.Obfs != "" && strings.EqualFold(sp.Obfs, "obfs") {
		return nil, errors.New("obfs: use plugin=obfs; the bare obfs flag carries no mode")
	}
	if plugin, inline := splitPlugin(sp.Plugin); plugin != "" {
		opts := sp.PluginOpts
		if inline != "" {
			if opts != "" {
				opts = inline + ";" + opts
			} else {
				opts = inline
			}
		}
		switch strings.ToLower(plugin) {
		case "obfs":
			mode := pluginValue(opts, "obfs")
			if mode == "" || strings.EqualFold(mode, "http") {
				network = "http"
				if p := pluginValue(opts, "path"); p != "" && sp.Path == "" {
					sp.Path = p
				}
			} else {
				return nil, fmt.Errorf("obfs=%s is not supported; use obfs=http", mode)
			}
		case "shadow-tls":
			sh, err := transport.ParseShadowTLS(opts)
			if err != nil {
				res.closeAll()
				return nil, err
			}
			handler = sh.Handler(handler)
			network = "tcp"
		case "v2ray-plugin":
			if strings.EqualFold(pluginValue(opts, "mode"), "websocket") || pluginValue(opts, "mode") == "" {
				network = "ws"
			}
		default:
			return nil, fmt.Errorf("plugin %q is not supported", plugin)
		}
	}

	in := &transport.Inbound{
		Network:     network,
		Path:        sp.Path,
		Host:        sp.Host,
		ServiceName: sp.ServiceName,
		TLS:         sp.TLS,
		TLSConfig:   tlsCfg,
		Reality:     re,
		StrictALPN:  rt.StrictALPN,
		XHTTP:       sp.XHTTP,
		Logger:      log,
		Relay:       srv.ServeSession,
	}

	var wrapped net.Listener
	effective := handler
	if res.ln != nil {
		wrapped, err = in.WrapListener(res.ln)
		if err != nil {
			res.closeAll()
			return nil, err
		}
		effective, err = in.WrapHandler(handler)
		if err != nil {
			_ = wrapped.Close()
			res.closeAll()
			return nil, err
		}
		res.ln = wrapped
	}
	srv.SetHandler(effective)

	if !needsUDP(sp.Protocol) {
		return res, nil
	}

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		res.closeAll()
		return nil, fmt.Errorf("listen udp %s: %w", addr, err)
	}
	switch sp.Protocol {
	case "hysteria":
		hs, err := hysteria.NewServer(hysteria.Options{
			Users:        users,
			TLSConfig:    tlsCfg,
			Congestion:   sp.Congestion,
			UpMbps:       sp.UpMbps,
			DownMbps:     sp.DownMbps,
			Brutal:       sp.BrutalSend > 0 && sp.BrutalReceive > 0,
			ObfsPassword: sp.ObfsPassword,
			Logger:       log,
			Relay:        srv.ServeSession,
		})
		if err != nil {
			_ = pc.Close()
			res.closeAll()
			return nil, err
		}
		res.closers = append(res.closers, hs)
		go func() {
			if err := hs.Serve(pc); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Warn("hysteria listener stopped", "err", err)
			}
		}()
	case "tuic":
		ts, err := tuic.NewServer(tuic.Options{
			Users:      users,
			TLSConfig:  tlsCfg,
			Congestion: sp.Congestion,
			UpMbps:     sp.UpMbps,
			DownMbps:   sp.DownMbps,
			Brutal:     sp.BrutalSend > 0 && sp.BrutalReceive > 0,
			Logger:     log,
			Relay:      srv.ServeSession,
		})
		if err != nil {
			_ = pc.Close()
			res.closeAll()
			return nil, err
		}
		res.closers = append(res.closers, ts)
		go func() {
			if err := ts.Serve(pc); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Warn("tuic listener stopped", "err", err)
			}
		}()
	default:
		// The protocol owns the datagram socket (PacketHandler).
		if ph, ok := effective.(core.PacketHandler); ok {
			res.pc = pc
			go func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if err := ph.ServePackets(ctx, pc); err != nil && !errors.Is(err, net.ErrClosed) {
					log.Warn("udp listener stopped", "err", err)
				}
			}()
		} else {
			_ = pc.Close()
		}
	}
	return res, nil
}

// splitPlugin splits "name;opt=val;..." into the plugin name and its inline
// option string.
func splitPlugin(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	parts := strings.Split(s, ";")
	name := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		return name, ""
	}
	return name, strings.TrimSpace(strings.Join(parts[1:], ";"))
}

func pluginValue(opts, key string) string {
	for _, part := range strings.Split(opts, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// serveTCP runs the accept loop until the listener closes.
func serveTCP(srv *core.Server, ln net.Listener, log *slog.Logger) {
	if ln == nil {
		return
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Warn("listener stopped", "err", err)
		}
	}()
}

// drainServer closes a server and waits a bounded time for sessions to finish.
func drainServer(srv *core.Server, timeout time.Duration) {
	if srv == nil {
		return
	}
	_ = srv.Close()
	_ = timeout
}
