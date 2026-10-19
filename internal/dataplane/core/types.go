// Package core is the kernel of kaze: connection acceptance, protocol sniffing,
// rule routing, DNS, per-user accounting and byte relay.
//
// The type shapes in this file follow the Go runtime type metadata recovered from
// the v0.5.18 binary (see notes/rev-core.md and REPORT.md §8). Offsets quoted in
// comments are the original struct offsets from that metadata; the Go field order
// below reproduces them so behaviour that depends on layout (splice, tracking)
// maps one-to-one onto the original.
package core

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Action is the resolved decision of a rule. Values are observed literally:
// block 0 / direct 1 / proxy 2 / dns 3 (REPORT.md §17.2.1, §18.1, §19.1).
type Action int

const (
	// ActionBlock rejects the session ("block", "reject", "blackhole").
	ActionBlock Action = 0
	// ActionDirect dials the destination itself ("direct", "freedom").
	ActionDirect Action = 1
	// ActionProxy dials through a named outbound ("proxy", or a route/outbound
	// action_value whose protocol is a real outbound).
	ActionProxy Action = 2
	// ActionDNS binds a Resolver to the rule; the resolver is injected into
	// ResolveWith so the candidate IPs satisfy the routing table.
	ActionDNS Action = 3
)

func (a Action) String() string {
	switch a {
	case ActionBlock:
		return "block"
	case ActionDirect:
		return "direct"
	case ActionProxy:
		return "proxy"
	case ActionDNS:
		return "dns"
	}
	return "unknown"
}

// User is one admitted account. Layout: ID int, UUID string, SpeedLimit int,
// DeviceLimit int (core.User @0xea5880, size 0x28).
type User struct {
	ID          int
	UUID        string
	SpeedLimit  int // Mbps; 0 = unlimited
	DeviceLimit int // concurrent devices; 0 = unlimited
}

// Resolver is the one-method interface behind ActionDNS (REPORT.md §19.2):
// LookupNetIP(ctx, "ip"|"ip4"|"ip6", host) ([]netip.Addr, error).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// PacketStream is a message-oriented UDP stream used by every UDP-capable
// protocol (xudp, socks5 associate, shadowsocks UDP, hysteria, tuic, mieru,
// snell, wireguard).
type PacketStream interface {
	ReadPacket(p []byte) (n int, addr socks.Addr, err error)
	WritePacket(p []byte, addr socks.Addr) error
	Close() error
}

// Outbound is the client side of a protocol. DialTCP must honour ctx.
type Outbound interface {
	Name() string
	DialTCP(ctx context.Context, addr socks.Addr) (net.Conn, error)
}

// UDPOutbound is an Outbound that can also carry datagrams. Outbounds that can
// reach UDP advertise it through this optional interface; the balancer checks it
// before selecting a member ("no outbound in the group carries UDP").
type UDPOutbound interface {
	Outbound
	DialPacket(ctx context.Context, addr socks.Addr) (PacketStream, error)
}

// Session is the result of a successful inbound handshake. Layout follows
// core.Session (size 0x60): UserID, Dest, Conn, Packets, Local, Socket.
type Session struct {
	UserID  int
	ConnID  uint64 // process-unique id, assigned by the server before relay
	Dest    socks.Addr
	Conn    net.Conn
	Packets PacketStream // non-nil for UDP sessions
	Local   netip.Addr   // node-side egress address, zero = unspecified
	Socket  *net.TCPConn // bare socket for splice, may be nil
}

// ChunkDirection is the relay direction of one accounted chunk: upload is
// client→remote, download is remote→client.
type ChunkDirection int

const (
	DirUpload ChunkDirection = iota
	DirDownload
)

// Chunk describes one chunk-accounted IO. N is the requested size on Begin and
// the completed size on Complete. Path is "conn" for stream sessions and "udp"
// for datagram sessions.
type Chunk struct {
	ConnID uint64
	UserID int
	Dir    ChunkDirection
	Path   string
	N      int64
	Err    error
}

// ChunkHook is the per-chunk accounting hook used by usage_v2 and the local
// event meter. Begin may refuse the chunk (quota exhausted, authorization
// revoked); the token it returns is handed back to Complete. Close is called
// once per session after its relay ends.
//
// Implementations run on the relay goroutines: Begin/Complete for one direction
// are always paired and ordered, but different sessions and the two directions
// of one session are concurrent.
type ChunkHook interface {
	Begin(Chunk) (token any, err error)
	Complete(Chunk, any)
	Close(Chunk)
}

// Handler is one inbound protocol as wired by node.buildHandler. Handle parses
// the handshake from conn and returns the session to relay. It must not read
// beyond the protocol handshake.
type Handler interface {
	Handle(ctx context.Context, conn net.Conn) (*Session, error)
}

// PacketHandler is implemented by inbound protocols that own a UDP socket
// (socks5 UDP ASSOCIATE, shadowsocks UDP, snell v3, mieru). The node passes the
// already-bound socket; the handler relays datagrams itself.
type PacketHandler interface {
	ServePackets(ctx context.Context, pc net.PacketConn) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, conn net.Conn) (*Session, error)

func (f HandlerFunc) Handle(ctx context.Context, conn net.Conn) (*Session, error) {
	return f(ctx, conn)
}

// Decision is what Router.Route returns.
type Decision struct {
	Action   Action
	Outbound Outbound // set when Action == ActionProxy
	Name     string   // rule name for logs / errors
	Resolver Resolver // set when Action == ActionDNS
}

// Rule is one routing rule. Fields are the observed core.Rule layout
// (size 0xd8). The matcher methods live in rule.go.
type Rule struct {
	Name     string
	Action   Action
	Outbound string
	Resolver Resolver

	suffixes map[string]struct{}
	fulls    map[string]struct{}
	keywords []string
	regexps  []*regexp.Regexp
	ranges   ipSet
	ports    []portRange
	protos   map[string]struct{}
	networks map[string]bool
	all      []*Rule

	// noMatch is set when every match token was unusable, which is reported as
	// "%s: the rule has no usable match" at build time.
	noMatch bool
}

// Router holds the ordered rule list and outbound table. Layout follows
// core.Router (size 0x38): Rules, BlockBitTorrent, BlockPrivate, Outbounds,
// Default.
type Router struct {
	Rules           []*Rule
	BlockBitTorrent bool
	BlockPrivate    bool
	Outbounds       map[string]Outbound
	Default         string

	// fallbackDefault is the default Outbound resolved from Default.
	fallbackDefault Outbound
}

// DayRange is an inclusive minute-of-day range, e.g. 20:00-02:00 wraps.
type DayRange struct {
	From int
	To   int
}

// Contains reports whether t's local minute-of-day is inside the range.
func (d DayRange) Contains(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	if d.From <= d.To {
		return m >= d.From && m < d.To
	}
	return m >= d.From || m < d.To
}

// Stranger marks a connection that did not look like one of our clients. The
// server either drops it quietly or answers like a web server ("Dismiss").
type Stranger struct {
	Conn  net.Conn
	Err   error
	Quiet bool
}

func (s *Stranger) Error() string {
	if s.Err != nil {
		return s.Err.Error()
	}
	return "stranger"
}

func (s *Stranger) Unwrap() error { return s.Err }

// IsStranger reports whether err wraps a *Stranger.
func IsStranger(err error) (*Stranger, bool) {
	var s *Stranger
	if errors.As(err, &s) {
		return s, true
	}
	return nil, false
}

// ErrBlocked is returned by Router.Route for ActionBlock; the message carries
// the rule name ("rule %s").
type ErrBlocked struct{ Rule string }

func (e *ErrBlocked) Error() string {
	if e.Rule == "" {
		return "blocked"
	}
	return "rule " + e.Rule
}

// AddrOf converts a net.Addr; convenience for handlers.
func AddrOf(n net.Addr) socks.Addr { return socks.FromNetAddr(n) }

// CloseWrite closes the write side when supported.
func CloseWrite(c net.Conn) error {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// KeepAlive applies the TCP keepalive policy observed in (*Server).handle.
func KeepAlive(c *net.TCPConn) {
	_ = c.SetKeepAlive(true)
	_ = c.SetKeepAlivePeriod(30 * time.Second)
}

// ipSet is a set of CIDR ranges with a lazily sorted interval view
// (core.ipSet: ranges []ipRange, sorted bool).
type ipSet struct {
	ranges []ipRange
	sorted bool
}

type ipRange struct {
	from netip.Addr
	to   netip.Addr
}

// portRange is an inclusive port interval.
type portRange struct {
	from uint16
	to   uint16
}

// counters used by node metrics.
type counters struct {
	sessions atomic.Int64
	refused  atomic.Int64
}

// copyBuf is the relay buffer size; the binary lets io.Copy use its default
// 32 KiB, and splice path uses the kernel pipe directly.
const copyBuf = 32 * 1024

var _ = io.Copy         // keep io imported for relay helpers in other files
var _ = strings.ToLower // used by rule matchers in other files
var _ sync.Mutex        // used by tracker/guard in other files
var _ = copyBuf
