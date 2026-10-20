// Package outbound is kaze's client protocol stack: it dials an upstream proxy
// on behalf of a routed session. The inbound protocols live in
// internal/proto/*; this package is the independent client half, exactly as in
// the sample (notes/rev-ops.md §2: "客户端侧协议栈，与入站是两套独立实现").
//
// The sample's entry point is github.com/ANRCM0/TX-Node/internal/dataplane/outbound.New @0xb74f60 (REPORT.md
// §9); the returned value is an *outbound.Proxy (@0xb76de0 Close, @0xb77860
// DialTCP) that wraps the protocol handshake plus the stream decorators listed
// in notes/funcs/outbound.txt (headerConn, lengthStream, chunkStream, perDest,
// xudpPacket, uotPacket, queue).
//
// Settings are read from opt.Opt, which is a zero-cost alias of
// map[string]any (REPORT.md §18.3): the panel's custom_outbounds Settings and
// StreamSettings are merged by node.mergeStream (§19.3) and handed here
// unchanged. Both Xray and sing-box spellings are accepted because the panels
// emit both (notes/rev-ops.md §2.2).
package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
	"github.com/ANRCM0/TX-Node/internal/dataplane/wgout"
)

// ErrNotSupported is the whitelist error. The text is the literal string
// observed in the dynamic run (REPORT.md §22.3) and is asserted verbatim by
// node's warning path:
//
//	WARN custom outbound "u": outbound type "…" is not supported;
//	     socks, http, wireguard, trojan, vless, vmess and shadowsocks are;
//	     traffic routed to it is blocked until this is fixed
//
// Note: catalog-strings.md #524 shows node.customOutbound also formats
// "custom outbound %q: %s; traffic routed to it is blocked until this is
// fixed"; node must therefore print this error without appending the tail
// again (agreed with the Lead).
type ErrNotSupported struct{ Protocol string }

func (e *ErrNotSupported) Error() string {
	return fmt.Sprintf("outbound type %q is not supported; socks, http, wireguard, trojan, vless, vmess and shadowsocks are; traffic routed to it is blocked until this is fixed", e.Protocol)
}

// supported is the strict whitelist from REPORT.md §22.3. anytls/naive/mieru/
// snell/tuic/hysteria are inbound protocols; §9's wider static list mistook
// inbound names for outbound types.
var supported = map[string]bool{
	"socks":       true,
	"http":        true,
	"wireguard":   true,
	"trojan":      true,
	"vless":       true,
	"vmess":       true,
	"shadowsocks": true,
}

// aliases is the outbound-side projection of conf's 16-entry protocol alias
// table (notes/rev-core.md: `v2ray→vmess`, `ss→shadowsocks`, `socks5→socks`,
// …). Only aliases that land on a whitelisted outbound type are accepted here;
// aliases for inbound-only protocols keep failing the whitelist.
var aliases = map[string]string{
	"v2ray":  "vmess",
	"ss":     "shadowsocks",
	"socks5": "socks",
}

// NormalizeProtocol maps an alias to its canonical outbound type. It is
// exported so node can build its cache key ("protocol|json(opt)", §19.3) from
// the same spelling that New resolves.
func NormalizeProtocol(protocol string) string {
	p := strings.ToLower(strings.TrimSpace(protocol))
	if a, ok := aliases[p]; ok {
		return a
	}
	return p
}

// New builds one outbound. The only inputs are the protocol name and the
// merged settings map, matching outbound.New's two arguments.
func New(protocol string, o opt.Opt) (core.Outbound, error) {
	if o == nil {
		o = opt.Opt{}
	}
	p := NormalizeProtocol(protocol)
	if !supported[p] {
		return nil, &ErrNotSupported{Protocol: protocol}
	}
	s := settings(o)

	switch p {
	case "wireguard":
		// REPORT.md §9: the WireGuard outbound is internal/wgout. FromSettings
		// is the panel/settings adapter (wgout.FromSettings @0xc8cc00).
		return wgout.FromSettings(o)
	case "socks":
		return newSocks(s)
	case "http":
		return newHTTP(s)
	case "vless":
		return newVLESS(s, o)
	case "vmess":
		return newVMess(s, o)
	case "trojan":
		return newTrojan(s, o)
	case "shadowsocks":
		return newShadowsocks(s, o)
	}
	return nil, &ErrNotSupported{Protocol: protocol}
}

// Proxy is the generic outbound behind every non-WireGuard protocol. It keeps
// the sample's shape: one type with DialTCP/ListenPacket, a stream description
// and a per-protocol request builder (outbound.(*Proxy).vlessRequest @0xb76ea0,
// .vlessStream @0xb773e0, .dial @0xb81c00, .raw @0xb81b20).
type Proxy struct {
	protocol string
	opt      opt.Opt
	stream   *stream

	addr     socks.Addr // the upstream server
	uuid     [16]byte
	password string
	method   string // shadowsocks cipher / vmess security in the panel dialect
	security byte   // vmess SecurityType byte
	flow     string
	alterID  int
	user     string

	mu          sync.Mutex
	via         []core.Outbound // _kaze_via chain, last hop closest to this outbound
	vmessOption byte
}

func (p *Proxy) Name() string { return p.protocol }

// Close releases nothing today: every DialTCP returns a fresh conn and the
// outbound holds no pool. The method exists because the sample's *Proxy has
// Close (outbound.(*Proxy).Close @0xb76de0) and node may call it.
func (p *Proxy) Close() error { return nil }

// SetVia installs the chain of outbounds used to reach this outbound's server
// (outbound.(*Proxy).SetVia @0xb81a20). node resolves panel.OutboundSpec.Via
// tag names to concrete outbounds and passes them through the "_kaze_via"
// setting (notes/rev-round3-outbound.md §1.3 step 5).
func (p *Proxy) SetVia(via ...core.Outbound) {
	p.mu.Lock()
	p.via = append([]core.Outbound(nil), via...)
	p.mu.Unlock()
}

// viaChain returns the configured chain.
func (p *Proxy) viaChain() []core.Outbound {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.via
}

// dialServer connects to the proxy server itself, honouring the via chain: the
// last entry is the hop closest to this outbound and dials the next one.
func (p *Proxy) dialServer(ctx context.Context) (net.Conn, error) {
	via := p.viaChain()
	if len(via) > 0 {
		return via[len(via)-1].DialTCP(ctx, p.addr)
	}
	var d net.Dialer
	d.Timeout = 15 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		d.Deadline = deadline
	}
	c, err := d.DialContext(ctx, "tcp", p.addr.String())
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", p.addr, err)
	}
	return c, nil
}

// dial opens the transport to the proxy server: raw TCP plus TLS/REALITY and
// the ws/http/h2/grpc/xhttp wrapper selected by streamSettings.
func (p *Proxy) dial(ctx context.Context) (net.Conn, error) {
	return p.openStream(ctx)
}

// DialTCP implements core.Outbound: it dials the upstream and performs the
// protocol request for dest.
func (p *Proxy) DialTCP(ctx context.Context, dest socks.Addr) (net.Conn, error) {
	c, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	out, err := p.request(ctx, c, dest)
	if err != nil {
		c.Close()
		return nil, err
	}
	return out, nil
}

// request performs the per-protocol request on an already-opened transport.
func (p *Proxy) request(ctx context.Context, c net.Conn, dest socks.Addr) (net.Conn, error) {
	switch p.protocol {
	case "vless":
		return p.vlessStream(c, dest)
	case "vmess":
		return p.vmessStream(c, dest)
	case "trojan":
		return p.trojanStream(c, dest)
	default:
		c.Close()
		return nil, fmt.Errorf("outbound %q: no TCP request builder", p.protocol)
	}
}

// DialPacket implements core.UDPOutbound for the protocols that can carry
// datagrams: native datagram, XUDP or UDP-over-TCP (notes/rev-ops.md §2.3).
func (p *Proxy) DialPacket(ctx context.Context, dest socks.Addr) (core.PacketStream, error) {
	switch p.protocol {
	case "trojan":
		return p.trojanPacket(ctx, dest)
	case "vless":
		if p.stream != nil && p.stream.udpOverTCP > 0 {
			return p.uotPacket(ctx, dest)
		}
		return p.xudpPacket(ctx, dest)
	case "vmess":
		if p.stream != nil && p.stream.udpOverTCP > 0 {
			return p.uotPacket(ctx, dest)
		}
		return nil, fmt.Errorf("outbound: no UDP for endpoint %q: a vmess outbound with security %s carries TCP only, so UDP routed to this outbound is dropped; set udp_over_tcp=true in its settings", dest, p.method)
	}
	return nil, fmt.Errorf("outbound: no UDP for endpoint %q", dest)
}

// readVia extracts the resolved chain from the "_kaze_via" / "via" setting.
// Values may be a single core.Outbound or a []core.Outbound in configuration
// order (last = closest to this outbound). Tag strings are rejected here
// because only node owns the name table.
func readVia(o opt.Opt) ([]core.Outbound, error) {
	v, ok := o["_kaze_via"]
	if !ok {
		v, ok = o["via"]
	}
	if !ok || v == nil {
		return nil, nil
	}
	switch t := v.(type) {
	case core.Outbound:
		if t == nil {
			return nil, nil
		}
		return []core.Outbound{t}, nil
	case []core.Outbound:
		out := make([]core.Outbound, 0, len(t))
		for _, ob := range t {
			if ob != nil {
				out = append(out, ob)
			}
		}
		return out, nil
	case []any:
		out := make([]core.Outbound, 0, len(t))
		for _, e := range t {
			ob, ok := e.(core.Outbound)
			if !ok {
				return nil, errViaUnresolved(e)
			}
			if ob != nil {
				out = append(out, ob)
			}
		}
		return out, nil
	default:
		return nil, errViaUnresolved(v)
	}
}

func errViaUnresolved(v any) error {
	return fmt.Errorf("via %q is not a resolved outbound: pass a core.Outbound (node resolves tag names before outbound.New)", fmt.Sprint(v))
}

// errEchNoConfig mirrors outbound.errEchNoConfig @0xb7d3c0.
func errEchNoConfig() error {
	return errors.New(`ECH is enabled without a config list: outbounds do not look it up in DNS, and the config has to be in the settings (ech_config, ech-config or echConfigList)`)
}
