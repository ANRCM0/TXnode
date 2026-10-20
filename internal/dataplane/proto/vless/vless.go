// Package vless implements the VLESS inbound of kaze v0.5.18: the request
// header, the two-byte response header, the cmd dispatch (1=TCP, 2=raw UDP,
// 3=mux) and the xtls-rprx-vision framing.
//
// Evidence (all addresses are file virtual addresses of the reference sample,
// SHA-256 723d4e20…f900):
//
//   - REPORT.md §6.2 (Vision + VLESS Encryption string inventory)
//   - REPORT.md §17.3.2 (5-byte Vision frame, b3/b4 are the padding length)
//   - REPORT.md §17.3.3 (cmd dispatch: 2 is plain UDP, 3 is mux)
//   - notes/rev-proto-tcp.md §1.1–§1.5 (header layout, addon TLV, flow checks)
//   - notes/rev-round2-proto.md §B/§C (appendFrame/endFrame, vision admission)
//   - notes/rev-round2b-proto.md §1.1–§1.6 (visionConn layout, tlsBuffers)
//
// The unsafe TLS-buffer optimisation behind vision "direct" frames lives in
// internal/tlsbuf (owned elsewhere); this package deliberately does not wrap
// crypto/tls internals. A peer that asks for a direct (cmd==2) frame therefore
// gets the same error the sample produces when its probe fails.
package vless

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Command bytes. notes/rev-round2-proto.md §C.1: 0xb3d9bf (cmp 3), 0xb3dad1
// (cmp 1), 0xb3dae0 (cmp 2); anything else is "vless: unsupported command"
// (0xb3dbfe → 0xf6eb6d, 26 bytes).
const (
	CmdTCP byte = 1
	CmdUDP byte = 2
	CmdMux byte = 3
)

// FlowVision is the only flow the sample knows. The literal is assembled from
// two movabs immediates at 0xb3d874/0xb3d87e ("xtls-rpr" + "x-vision").
const FlowVision = "xtls-rprx-vision"

// The mux pseudo-destination. Handshake allocates it inline at 0xb3da42
// (len 0xb = 11, pointer 0xf5cd93 "v1.mux.cool") with port 0x29a = 666
// (0xb3da55).
const (
	MuxAddress = "v1.mux.cool"
	MuxPort    = 666
)

// Errors reproduce the sample's literals byte for byte so tests can assert on
// them (REPLICATION.md §0.5).
var (
	// 0xf659d4, 15 bytes.
	ErrUnknownUser = errors.New("vless: unknown user")
	// 0xf659e7, 19 bytes (readDest, domain length byte == 0).
	ErrEmptyDomain = errors.New("vless: empty domain")
	// 0xf6a9ab, 22 bytes (readDest, unknown ATYP).
	ErrBadAddressType = errors.New("vless: bad address type")
	// 0xf6eb6d, 26 bytes.
	ErrUnsupportedCommand = errors.New("vless: unsupported command")
	// 0xf80b2a, 38 bytes: flow=vision with cmd==2 (0xb3d7d4/0xb3d845).
	ErrVisionPlainUDP = errors.New("vless: Vision does not carry plain UDP")
	// 0xf8d10b, 49 bytes: node forces Vision, client sent no flow on TCP
	// (0xb3d8b8/0xb3d8c9).
	ErrVisionRequired = errors.New("vless: this node requires the Vision flow for TCP")
	// 0xf87489, 44 bytes.
	ErrVisionNeedsTLS13 = errors.New("vless: Vision needs TLS 1.3 directly on TCP")
	// 0xf72f80, 29 bytes: endFrame saw a cmd outside {0,1,2}.
	ErrUnknownVisionCommand = errors.New("vless: unknown Vision command")
	// 0xf92f0b, 57 bytes: vless.tlsBuffers probe failed (0xb3ab87). The sample
	// returns it verbatim (no "vless:" prefix) from the vision direct path.
	ErrTLSInternals = errors.New("this Go version's TLS internals are not what kaze expects")
)

// Options is the inbound configuration (REPLICATION.md §3.2).
//
//   - Users: admitted accounts; UUID is the VLESS user id.
//   - Decryption: the node's "decryption" string (see ParseDecryption). Empty
//     means plain VLESS. UNVERIFIED: the encrypted record layer is not
//     reproduced yet, see enc.go.
//   - Flow: the node's own flow setting; FlowVision makes Vision mandatory for
//     TCP ("this node requires the Vision flow for TCP").
//   - AllowVision: whether this node offers xtls-rprx-vision to clients.
//   - Logger: optional.
//   - MuxPackets: optional hook that wraps the underlying connection into the
//     mux packet stream (internal/proto/xudp.Stream in the sample: the itab
//     0xfc73c0 is loaded at 0xb3da5b). node wires it; nil disables the UDP part
//     of mux sessions but keeps TCP mux working.
//   - VisionUUIDPrefix: reproduce the sample's 16-byte UUID prefix on the first
//     Vision frame (0xb3b71e/0xb3b789). Default off; see vision.go.
type Options struct {
	Users            []core.User
	Decryption       string
	Flow             string
	AllowVision      bool
	Logger           *slog.Logger
	MuxPackets       func(conn net.Conn) core.PacketStream
	VisionUUIDPrefix bool
}

// Handler is the VLESS inbound.
type Handler struct {
	users map[[16]byte]*core.User

	flow        string
	allowVision bool
	logger      *slog.Logger
	muxPackets  func(net.Conn) core.PacketStream
	visionUUID  bool

	enc *EncServer // nil when Decryption is empty
}

// NewHandler validates the configuration. Users with a malformed UUID are
// rejected: the sample keeps a map[[16]byte]*core.User (0xb3d0e0 uses the
// 16-byte key directly), so a bad UUID can never match a request.
func NewHandler(o Options) (*Handler, error) {
	h := &Handler{
		users:       make(map[[16]byte]*core.User, len(o.Users)),
		flow:        o.Flow,
		allowVision: o.AllowVision,
		logger:      o.Logger,
		muxPackets:  o.MuxPackets,
		visionUUID:  o.VisionUUIDPrefix,
	}
	if h.logger == nil {
		h.logger = slog.New(slog.DiscardHandler)
	}
	if o.Flow != "" && o.Flow != FlowVision {
		// conf.validateLocalSecurity rejects this earlier with
		// "%sflow=%s is not supported; use xtls-rprx-vision or leave it out";
		// keep the handler honest as well.
		return nil, fmt.Errorf("vless: flow %q is not supported; use %s or leave it out", o.Flow, FlowVision)
	}
	h.SetUsers(o.Users)
	if o.Decryption != "" {
		dec, err := ParseDecryption(o.Decryption)
		if err != nil {
			return nil, err
		}
		h.enc = dec.Server(h.logger)
	}
	return h, nil
}

// SetUsers replaces the user table (the sample exposes (*Handler).SetUsers at
// 0xb3c6e0 for panel hot updates).
func (h *Handler) SetUsers(users []core.User) {
	m := make(map[[16]byte]*core.User, len(users))
	for i := range users {
		id, err := ParseUUID(users[i].UUID)
		if err != nil {
			continue
		}
		u := users[i]
		m[id] = &u
	}
	h.users = m
}

// Handle parses one VLESS request and returns the session to relay. It never
// reads past the request header (REPLICATION.md §3.2).
func (h *Handler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	if h.enc != nil {
		enc, err := h.enc.Handshake(conn)
		if err != nil {
			return nil, err
		}
		conn = enc
	}
	req, err := h.readRequest(conn)
	if err != nil {
		return nil, err
	}

	// Flow admission, notes/rev-proto-tcp.md §1.3 and notes/rev-round2-proto.md
	// §C.3. The checks run before the address for cmd==3 and after it otherwise;
	// the observable order only matters for the error the client sees, and the
	// sample reports the flow error first.
	vision := false
	switch {
	case req.Flow == FlowVision:
		if !h.allowVision {
			return nil, fmt.Errorf("vless: client asked for flow %q, which this node does not offer", req.Flow)
		}
		if req.Cmd == CmdUDP {
			return nil, ErrVisionPlainUDP
		}
		vision = true
	case req.Flow != "":
		return nil, fmt.Errorf("vless: client asked for flow %q, which this node does not offer", req.Flow)
	case req.Flow == "" && h.flow == FlowVision && req.Cmd == CmdTCP:
		return nil, ErrVisionRequired
	}

	// cmd==3 is dispatched before the address is read (0xb3d9bf precedes the
	// 0xb3daa0 call to readDest), so a mux request carries no destination.
	if req.Cmd == CmdMux {
		return h.muxSession(ctx, conn, req)
	}

	dest, err := readDest(conn)
	if err != nil {
		return nil, err
	}
	req.Dest = dest

	switch req.Cmd {
	case CmdTCP:
	case CmdUDP:
	default:
		return nil, ErrUnsupportedCommand
	}

	if req.Cmd == CmdTCP && !vision && h.enc == nil {
		if reader := core.NewReadPauseConn(conn); reader != nil {
			conn = reader
		}
	}
	rc := &respConn{Conn: conn}
	var out net.Conn = rc
	if vision {
		vc, err := newVisionConn(rc, conn, req.UUID, h.visionUUID)
		if err != nil {
			return nil, err
		}
		out = vc
	}

	sess := &core.Session{
		UserID: req.UserID,
		Dest:   req.Dest,
		Conn:   out,
	}
	if req.Cmd == CmdUDP {
		sess.Packets = &packetStream{conn: out, dest: req.Dest}
	}
	return sess, nil
}

// muxSession builds the cmd==3 session: destination v1.mux.cool:666 with the
// mux packet stream on top of the connection (0xb3d9e5–0xb3da89).
func (h *Handler) muxSession(ctx context.Context, conn net.Conn, req *request) (*core.Session, error) {
	_ = ctx // the handshake has no timeout of its own; node bounds it on the conn
	rc := &respConn{Conn: conn}
	sess := &core.Session{
		UserID: req.UserID,
		Dest:   socks.Addr{Host: MuxAddress, Port: MuxPort},
		Conn:   rc,
	}
	if h.muxPackets != nil {
		sess.Packets = h.muxPackets(rc)
	}
	return sess, nil
}

// request is the parsed VLESS header.
type request struct {
	UUID   [16]byte
	UserID int
	Flow   string
	Cmd    byte
	Dest   socks.Addr
}

// readRequest follows the five read steps of (*Handler).Handshake @0xb3c880
// (notes/rev-proto-tcp.md §1.1):
//
//	0xb3c9ef  ver       1 byte, must be 0 (0xb3cc4d cmp byte [rcx],0)
//	0xb3ce88  uuid[16] + addonLen   17 bytes
//	0xb3d3b9  addon[addonLen]
//	0xb3d4b8  cmd       1 byte
//	0xb3daa0  readDest  port|atyp|addr
func (h *Handler) readRequest(r io.Reader) (*request, error) {
	var one [1]byte
	if _, err := io.ReadFull(r, one[:]); err != nil {
		return nil, err
	}
	if one[0] != 0 {
		// UNVERIFIED: the sample only compares the byte with zero at 0xb3cc4d;
		// no literal error string was recovered for this branch.
		return nil, fmt.Errorf("vless: unsupported version %d", one[0])
	}

	var head [17]byte // uuid 16 + addon length
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	req := &request{}
	copy(req.UUID[:], head[:16])
	addonLen := int(head[16])

	// User lookup happens right after the addon slice is read (mapaccess2 at
	// 0xb3d115 with a 16-byte key), before the command byte.
	u, ok := h.users[req.UUID]
	if !ok {
		return nil, ErrUnknownUser
	}
	req.UserID = u.ID

	if addonLen > 0 {
		addon := make([]byte, addonLen)
		if _, err := io.ReadFull(r, addon); err != nil {
			return nil, err
		}
		req.Flow = parseAddons(addon)
	}

	if _, err := io.ReadFull(r, one[:]); err != nil {
		return nil, err
	}
	req.Cmd = one[0]
	return req, nil
}

// parseAddons walks the hand-written protobuf TLV loop at 0xb3d3e2–0xb3d451:
// only field 1 with wire type 2 carries data (the flow string). Unknown fields
// are skipped by their length.
func parseAddons(b []byte) string {
	var flow string
	for len(b) >= 2 {
		tag := b[0]
		wire := tag & 7
		n := int(b[1])
		if wire != 2 {
			if n+2 > len(b) {
				break
			}
			b = b[n+2:]
			continue
		}
		if n+2 > len(b) {
			break
		}
		if tag>>3 == 1 {
			flow = string(b[2 : 2+n])
		}
		b = b[n+2:]
	}
	return flow
}

// readDest is vless.readDest @0xb3e760: one 3-byte read for [port BE16][atyp],
// then the address body. ATYP 1=IPv4, 2=domain, 3=IPv6 (0xb3e7e9).
func readDest(r io.Reader) (socks.Addr, error) {
	var head [3]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return socks.Addr{}, err
	}
	port := uint16(head[0])<<8 | uint16(head[1])
	var a socks.Addr
	a.Port = port
	switch head[2] {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return socks.Addr{}, err
		}
		a.Host = net.IP(b[:]).String()
	case 2:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return socks.Addr{}, err
		}
		if l[0] == 0 {
			return socks.Addr{}, ErrEmptyDomain
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return socks.Addr{}, err
		}
		a.Host = string(b)
	case 3:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return socks.Addr{}, err
		}
		a.Host = net.IP(b[:]).String()
	default:
		return socks.Addr{}, ErrBadAddressType
	}
	return a, nil
}

// respConn writes the two-byte VLESS response header ("\x00\x00": version 0,
// addon length 0) exactly once, prefixed to the first payload write.
//
// Evidence: (*respConn).Write @0xb3ea40 writes a word of zero (0xb3eb72
// "mov word ptr [rax], 0") followed by the payload in one write, and guards the
// header with a flag (see (*respConn).Pending @0xb3edc0). The pool.Get /
// growslice sequence around it is buffer reuse, not protocol.
type respConn struct {
	net.Conn

	mu      sync.Mutex
	written bool
	err     error
}

// Write sends the response header in front of the first payload byte.
func (c *respConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	if c.written {
		n, err := c.Conn.Write(p)
		if err != nil {
			c.err = err
		}
		return n, err
	}
	buf := make([]byte, 2+len(p))
	copy(buf[2:], p)
	n, err := c.Conn.Write(buf)
	c.written = true
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.err = err
	}
	return max(0, n-2), err
}

func (c *respConn) ReadPauseSupported() bool {
	_, ok := c.Conn.(*core.ReadPauseConn)
	return ok
}

func (c *respConn) PauseRead() error {
	if reader, ok := c.Conn.(core.ReadPauser); ok {
		return reader.PauseRead()
	}
	return core.ErrReadPauseUnsupported
}

func (c *respConn) ResumeRead() error {
	if reader, ok := c.Conn.(core.ReadPauser); ok {
		return reader.ResumeRead()
	}
	return core.ErrReadPauseUnsupported
}

func (c *respConn) ReadDeadline() time.Time {
	if reader, ok := c.Conn.(interface{ ReadDeadline() time.Time }); ok {
		return reader.ReadDeadline()
	}
	return time.Time{}
}

// Pending reports whether the response header is still unsent. core.Splice
// consults it before taking the zero-copy path ((*respConn).Pending @0xb3edc0).
func (c *respConn) Pending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.written
}

// ReadsFrom / WritesTo expose the wrapped connection so core.Splice can reach
// the real socket (the sample implements both: 0xb3ee20 / 0xb3ee00).
func (c *respConn) ReadsFrom() net.Conn { return c.Conn }
func (c *respConn) WritesTo() net.Conn  { return c.Conn }

// CloseWrite half-closes the underlying connection.
func (c *respConn) CloseWrite() error { return core.CloseWrite(c.Conn) }
