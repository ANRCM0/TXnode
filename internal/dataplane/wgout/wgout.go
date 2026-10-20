// Package wgout is kaze's WireGuard outbound: a userspace WireGuard peer on
// top of wireguard-go's netstack, used to egress through WARP or any other
// WireGuard endpoint.
//
// Sample evidence (notes/rev-ops.md §3, REPORT.md §9):
//
//	wgout.New        @0xc8a300   builds the device, bind and peer
//	wgout.FromSettings @0xc8cc00 panel/config → New adapter
//	wgout.keyHex     @0xc8a240   "a WireGuard key must be 32 bytes in base64"
//	(*reservedBind)  @0xc8c920   WARP reserved-byte bind wrapper
//	(*Outbound)      @0xc8b660   DialTCP / ListenPacket
//
// Default endpoint and peer key are Cloudflare WARP's, so a node can become a
// WARP client without wgcf: engage.cloudflareclient.com:2408 with
// bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=.
package wgout

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// WARP defaults, referenced from wgout.New's rodata (notes/rev-ops.md §3).
const (
	DefaultEndpoint  = "engage.cloudflareclient.com:2408"
	WARPPublicKey    = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	defaultLocal     = "172.16.0.2/32"
	defaultMTU       = 1280
	defaultKeepalive = 25
)

// Settings keys, accepting the spellings the panels emit (snake, camel and
// kebab; notes/rev-ops.md §3).
var (
	keysPrivateKey = []string{"private_key", "privateKey", "private-key"}
	keysPublicKey  = []string{"public_key", "publicKey", "public-key"}
	keysPSK        = []string{"preshared_key", "presharedKey", "pre_shared_key", "preSharedKey", "pre-shared-key"}
	keysAllowedIP  = []string{"allowed_ip", "allowedIP", "allowed-ip", "allowed_ips", "allowedIPs"}
	keysEndpoint   = []string{"endpoint", "server", "address"}
	keysMTU        = []string{"mtu"}
	keysKeepalive  = []string{"persistent_keepalive_interval", "persistentKeepaliveInterval", "persistent-keepalive-interval", "keepalive"}
	keysReserved   = []string{"reserved"}
	keysLocal      = []string{"local_address", "localAddress", "local-address", "addresses", "local_addr"}
)

// keyHex decodes a WireGuard key: 32 bytes in standard base64
// (wgout.keyHex @0xc8a240). The error text is the sample's.
func keyHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("a WireGuard key must be 32 bytes in base64")
	}
	if len(b) != 32 {
		return nil, errors.New("a WireGuard key must be 32 bytes in base64")
	}
	return b, nil
}

// hexString renders a WireGuard key for the UAPI config.
func hexString(b []byte) string { return hex.EncodeToString(b) }

// get is the small multi-spelling reader shared by New/FromSettings.
func get(o opt.Opt, keys ...string) (any, bool) {
	for _, k := range keys {
		if v, ok := o[k]; ok && v != nil {
			return v, true
		}
	}
	return nil, false
}

func str(o opt.Opt, keys ...string) string {
	v, ok := get(o, keys...)
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(t)
	}
}

func integer(o opt.Opt, def int, keys ...string) int {
	s := strings.TrimSpace(str(o, keys...))
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// list reads allowed_ip / reserved / local_address lists.
func list(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case string:
		var out []string
		for _, f := range strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			if f = strings.TrimSpace(f); f != "" {
				out = append(out, f)
			}
		}
		return out
	case float64:
		return []string{strconv.FormatFloat(t, 'f', -1, 64)}
	case int:
		return []string{strconv.Itoa(t)}
	}
	return nil
}

// Outbound is the WireGuard egress (wgout.(*Outbound)). It keeps the netstack
// device and answers DialTCP/DialPacket from it.
type Outbound struct {
	dev  *device.Device
	tnet *netstack.Net

	mu     sync.Mutex
	closed bool
}

// New builds a WireGuard outbound from a settings map (wgout.New @0xc8a300).
func New(o opt.Opt) (core.Outbound, error) {
	return newOutbound(o)
}

// FromSettings is the panel adapter (wgout.FromSettings @0xc8cc00). It unwraps
// a nested "settings" object and reports a bad shape as
// "the WireGuard outbound's settings cannot be read: %v".
func FromSettings(o opt.Opt) (core.Outbound, error) {
	if o == nil {
		return nil, errors.New("the WireGuard outbound has no private key")
	}
	switch sub := o["settings"].(type) {
	case map[string]any:
		o = opt.Opt(sub)
	case opt.Opt:
		o = sub
	}
	ob, err := newOutbound(o)
	if err != nil {
		var notKeyErr *missingKeyError
		if errors.As(err, &notKeyErr) {
			return nil, err
		}
		return nil, fmt.Errorf("the WireGuard outbound's settings cannot be read: %w", err)
	}
	return ob, nil
}

// missingKeyError keeps "the WireGuard outbound has no private key" unwrapped
// by FromSettings, matching the sample's literal message.
type missingKeyError struct{}

func (*missingKeyError) Error() string { return "the WireGuard outbound has no private key" }

func newOutbound(o opt.Opt) (*Outbound, error) {
	privateStr := str(o, keysPrivateKey...)
	if privateStr == "" {
		return nil, &missingKeyError{}
	}
	privateKey, err := keyHex(privateStr)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}

	publicStr := str(o, keysPublicKey...)
	if publicStr == "" {
		publicStr = WARPPublicKey
	}
	publicKey, err := keyHex(publicStr)
	if err != nil {
		return nil, fmt.Errorf("peer public key: %w", err)
	}

	var psk []byte
	if s := str(o, keysPSK...); s != "" {
		psk, err = keyHex(s)
		if err != nil {
			return nil, fmt.Errorf("preshared key: %w", err)
		}
	}

	endpoint := str(o, keysEndpoint...)
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if _, _, err := net.SplitHostPort(endpoint); err != nil {
		return nil, fmt.Errorf("endpoint %q must be host:port", endpoint)
	}

	allowed := []string{"0.0.0.0/0", "::/0"}
	if v, ok := get(o, keysAllowedIP...); ok {
		allowed = list(v)
	}
	for i, a := range allowed {
		if _, err := netip.ParsePrefix(a); err != nil {
			return nil, fmt.Errorf("allowed IP %q must be a prefix such as 0.0.0.0/0", a)
		}
		allowed[i] = a
	}
	allowed = normalizeAllowed(allowed)

	local := []string{defaultLocal}
	if v, ok := get(o, keysLocal...); ok {
		if l := list(v); len(l) > 0 {
			local = l
		}
	}
	var localAddrs []netip.Addr
	for _, l := range local {
		p, err := parseLocal(l)
		if err != nil {
			return nil, fmt.Errorf("local_address %q is not an address: %w", l, err)
		}
		localAddrs = append(localAddrs, p)
	}

	mtu := integer(o, defaultMTU, keysMTU...)
	if mtu < 576 || mtu > 65535 {
		mtu = defaultMTU
	}
	keepalive := integer(o, defaultKeepalive, keysKeepalive...)

	reserved, err := parseReserved(o)
	if err != nil {
		return nil, err
	}

	// netstack device: userspace TCP/IP over the tunnel.
	tunDev, tnet, err := netstack.CreateNetTUN(localAddrs, nil, mtu)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	bind := conn.NewDefaultBind()
	if len(reserved) > 0 {
		rb := &reservedBind{Bind: bind}
		copy(rb.reserved[:], reserved)
		bind = rb
	}
	dev := device.NewDevice(tunDev, bind, device.NewLogger(device.LogLevelError, "wgout: "))

	var cfg strings.Builder
	cfg.WriteString("private_key=" + hexString(privateKey) + "\n")
	cfg.WriteString("replace_peers=true\n")
	cfg.WriteString("public_key=" + hexString(publicKey) + "\n")
	if len(psk) > 0 {
		cfg.WriteString("preshared_key=" + hexString(psk) + "\n")
	}
	cfg.WriteString("endpoint=" + endpoint + "\n")
	if keepalive > 0 {
		cfg.WriteString("persistent_keepalive_interval=" + strconv.Itoa(keepalive) + "\n")
	}
	for _, a := range allowed {
		cfg.WriteString("allowed_ip=" + a + "\n")
	}
	cfg.WriteString("\n")
	if err := dev.IpcSet(cfg.String()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	return &Outbound{dev: dev, tnet: tnet}, nil
}

// normalizeAllowed drops the default dual-stack pair when a v4-only tunnel is
// requested, and keeps the caller's order.
func normalizeAllowed(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, a := range in {
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// parseLocal accepts "172.16.0.2" or "172.16.0.2/32" or "fd00::2/128".
func parseLocal(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, err
		}
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

// parseReserved reads the WARP reserved bytes: three bytes as "1,2,3",
// [1,2,3] or a JSON array of numbers.
func parseReserved(o opt.Opt) ([]byte, error) {
	v, ok := get(o, keysReserved...)
	if !ok {
		return nil, nil
	}
	parts := list(v)
	if len(parts) == 1 && strings.Contains(parts[0], "/") {
		parts = list(strings.ReplaceAll(parts[0], "/", ","))
	}
	if len(parts) == 0 {
		return nil, nil
	}
	out := make([]byte, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("reserved %q must be up to three bytes between 0 and 255", p)
		}
		out = append(out, byte(n))
	}
	if len(out) > 3 {
		out = out[:3]
	}
	return out, nil
}

// Name satisfies core.Outbound.
func (o *Outbound) Name() string { return "wireguard" }

// DialTCP dials dest through the tunnel. Hostnames are resolved by the
// netstack's own resolver ("cannot resolve %s through the tunnel").
func (o *Outbound) DialTCP(ctx context.Context, dest socks.Addr) (net.Conn, error) {
	addr := net.JoinHostPort(dest.Host, strconv.Itoa(int(dest.Port)))
	c, err := o.tnet.DialContext(ctx, "tcp", addr)
	if err != nil {
		if dest.IsDomain() && isResolveError(err) {
			return nil, fmt.Errorf("cannot resolve %s through the tunnel", dest.Host)
		}
		return nil, err
	}
	return c, nil
}

// isResolveError reports whether the netstack failed to resolve the name.
func isResolveError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such host") || strings.Contains(msg, "cannot resolve") || strings.Contains(msg, "not found")
}

// DialPacket opens a UDP "connection" through the tunnel.
func (o *Outbound) DialPacket(ctx context.Context, dest socks.Addr) (core.PacketStream, error) {
	ip := dest.IP()
	if !ip.IsValid() {
		return nil, fmt.Errorf("cannot resolve %s through the tunnel", dest.Host)
	}
	conn, err := o.tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(ip, dest.Port))
	if err != nil {
		return nil, err
	}
	return &packetConn{conn: conn, dest: dest}, nil
}

// Close tears the device down (wgout.(*Outbound).Close @0xc8c8e0).
func (o *Outbound) Close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	o.mu.Unlock()
	// wireguard-go's Device.Close closes the tun it was given; closing it a
	// second time panics inside netstack.
	o.dev.Close()
	<-o.dev.Wait()
	return nil
}

// packetConn adapts the netstack UDP endpoint to core.PacketStream
// (wgout.(*packetConn): pump/WriteTo/ReadFrom/SetReadDeadline/Close).
type packetConn struct {
	conn interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
		SetReadDeadline(time.Time) error
	}
	dest socks.Addr
}

func (p *packetConn) ReadPacket(b []byte) (int, socks.Addr, error) {
	n, err := p.conn.Read(b)
	if err != nil {
		return 0, socks.Addr{}, err
	}
	return n, p.dest, nil
}

func (p *packetConn) WritePacket(b []byte, a socks.Addr) error {
	_, err := p.conn.Write(b)
	return err
}

func (p *packetConn) Close() error { return p.conn.Close() }

// SetReadDeadline lets the relay bound a UDP read; timeoutError is the
// net.Error the sample returns.
func (p *packetConn) SetReadDeadline(t time.Time) error { return p.conn.SetReadDeadline(t) }

// timeoutError is wgout.timeoutError (@0xc8c200 value, @0xc8e1c0 pointer).
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Error = timeoutError{}

// reservedBind inserts WARP's three reserved bytes into the WireGuard message
// header. A WireGuard header is [type][reserved:3][…]; the reserved bytes must
// be zero for a normal peer, and Cloudflare uses them to select the client
// (wgout.(*reservedBind), @0xc8c920-@0xc8cb40).
type reservedBind struct {
	conn.Bind
	reserved [3]byte
}

func (b *reservedBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, buf := range bufs {
		if len(buf) >= 4 {
			copy(buf[1:4], b.reserved[:])
		}
	}
	return b.Bind.Send(bufs, ep)
}

func (b *reservedBind) BatchSize() int            { return b.Bind.BatchSize() }
func (b *reservedBind) Close() error              { return b.Bind.Close() }
func (b *reservedBind) SetMark(mark uint32) error { return b.Bind.SetMark(mark) }
func (b *reservedBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.Bind.ParseEndpoint(s)
}
func (b *reservedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return b.Bind.Open(port)
}

var (
	_ core.Outbound     = (*Outbound)(nil)
	_ core.UDPOutbound  = (*Outbound)(nil)
	_ core.PacketStream = (*packetConn)(nil)
	_ conn.Bind         = (*reservedBind)(nil)
)
