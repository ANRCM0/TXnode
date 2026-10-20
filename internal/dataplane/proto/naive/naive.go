// Package naive is the naive inbound of kaze v0.5.18.
//
// Evidence:
//   - REPORT.md §6.1 (TCP; HTTP/2 CONNECT semantics, "naive: authentication
//     failed", the decoy page), §20.5 (`naive` + REALITY is refused:
//     "Naive clients do not speak REALITY; set the node's security to TLS").
//   - notes/rev-proto-tcp.md §7 (18 functions / 4,032 B):
//     naive.(*Handler).Handshake @0xad4900 calls httpproxy.(*Handler).User
//     @0x966f00 (the credentials are the HTTP proxy's Basic auth),
//     naive.destination @0xad4ba0 (net.SplitHostPort; a host whose first byte is
//     '0' is compared with "sp.v2.udp-over-tcp.arpa" (23 B @0xf6a897) and
//     "sp.udp-over-tcp.arpa" (20 B @0xf66c8a) before falling back to
//     httpproxy.ParseDest), naive.PaddingHeader @0xad4ca0 (see below),
//     naive.(*Conn).Read/Write (the data path).
//   - notes/rev-proto-tcp.md §7.1 spells out PaddingHeader instruction by
//     instruction: len = 0x1e + rand(0x20) → 30..61 bytes; the first 16 bytes come
//     from the 16-character table "!#$()+<>?@[]^`{}" (@0xf61cdf) with a 64-bit
//     random shifted by 4 bits per byte; the rest is '~' (0x7e).
//   - notes/catalog-strings.md: `!#$()+<>?@[]^`{}kaze decoy page` is one rodata
//     blob — the padding charset is immediately followed by the decoy-page marker
//     that transport.newDecoySite uses. The naive package's own decoy response is
//     the literal "HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.24.0\r\n
//     Date: " @0xf96186.
//
// The connection between the transport and this handler is the interface
// transport.(*naiveStream) implements (@0xab5300 ProxyAuthorization returns the
// `Proxy-Authorization` header, @0xab5340 Authority reads the
// `-connect-authority` header, @0xab53e0 Accept yields the data connection).
package naive

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/httpproxy"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// paddingChars is the 16-byte table at 0xf61cdf (notes §7.1).
const paddingChars = "!#$()+<>?@[]^`{}"

// DecoyMarker is the decoy page marker that follows the padding table in rodata
// (transport.newDecoySite builds the page in memory, REPORT.md §7.9).
const DecoyMarker = "kaze decoy page"

// decoyHead is the literal head of the decoy response @0xf96186.
const decoyHead = "HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.24.0\r\nDate: "

// udp-over-tcp pseudo destinations (naive.destination @0xad4ba0).
const (
	udpOverTCPv2 = "sp.v2.udp-over-tcp.arpa"
	udpOverTCP   = "sp.udp-over-tcp.arpa"
)

// Error strings.
var (
	// ErrAuthFailed ← "naive: authentication failed" @0xf71825.
	ErrAuthFailed = errors.New("naive: authentication failed")
	// ErrNotTransport ← "naive: the connection did not come through the Naive
	// transport" @0xf96148.
	ErrNotTransport = errors.New("naive: the connection did not come through the Naive transport")
	// ErrNoAuthority guards a CONNECT without a destination.
	ErrNoAuthority = errors.New("naive: request without a server")
)

// Stream is the h2 CONNECT view of a connection, implemented by
// transport.(*naiveStream) (methods at @0xab5300 / @0xab5340 / @0xab53e0).
type Stream interface {
	net.Conn
	ProxyAuthorization() string
	Authority() string
	Accept() net.Conn
}

// Options is the package contract (REPLICATION.md §3.2).
type Options struct {
	Users []core.User
}

// Handler is the naive inbound. It reuses the HTTP proxy credential check
// (naive.(*Handler).Handshake calls httpproxy.(*Handler).User).
type Handler struct {
	proxy *httpproxy.Handler
}

var _ core.Handler = (*Handler)(nil)

// NewHandler validates Options and builds the handler.
func NewHandler(o Options) (*Handler, error) {
	proxy, err := httpproxy.NewHandler(httpproxy.Options{Users: o.Users})
	if err != nil {
		return nil, err
	}
	return &Handler{proxy: proxy}, nil
}

// Handle authenticates the CONNECT request and returns the session.
//
// Two entry shapes are supported:
//   - conn implements Stream: the transport already parsed the HTTP/2 CONNECT
//     (this is the binary's path, ending in the type assertion at the end of
//     Handshake),
//   - otherwise an HTTP/1.1 CONNECT head is parsed from the connection, which is
//     what a plain TLS-wrapped naive client produces.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	if st, ok := conn.(Stream); ok {
		return h.fromStream(st)
	}
	return h.fromHTTP1(conn)
}

func (h *Handler) fromStream(st Stream) (*core.Session, error) {
	user, ok := h.proxy.User(st.ProxyAuthorization())
	if !ok {
		return nil, ErrAuthFailed
	}
	dest, err := Destination(st.Authority())
	if err != nil {
		return nil, err
	}
	var data net.Conn
	if padded, ok := st.(interface {
		PaddingRequested() bool
		AcceptPadding(string) net.Conn
	}); ok && padded.PaddingRequested() {
		data = padded.AcceptPadding(PaddingHeader())
		if data != nil {
			data = &paddingConn{Conn: data}
		}
	} else {
		data = st.Accept()
	}
	if data == nil {
		return nil, ErrNotTransport
	}
	userID := 0
	if user != nil {
		userID = user.ID
	}
	return &core.Session{UserID: userID, Dest: dest, Conn: data}, nil
}

// fromHTTP1 handles a plain HTTP/1.1 CONNECT.
func (h *Handler) fromHTTP1(conn net.Conn) (*core.Session, error) {
	br := bufio.NewReaderSize(conn, 4096)
	head, err := readHead(br, 8<<10)
	if err != nil {
		_ = WriteDecoyResponse(conn)
		return nil, ErrNotTransport
	}
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(string(head))))
	if err != nil {
		_ = WriteDecoyResponse(conn)
		return nil, ErrNotTransport
	}
	user, ok := h.proxy.User(req.Header.Get("Proxy-Authorization"))
	if !ok || req.Method != http.MethodConnect {
		_ = WriteDecoyResponse(conn)
		if !ok {
			return nil, ErrAuthFailed
		}
		return nil, ErrNotTransport
	}
	dest, err := Destination(req.Host)
	if err != nil {
		return nil, err
	}
	// The 200 carries the padding header, produced by naive.PaddingHeader.
	resp := "HTTP/1.1 200 OK\r\n"
	padded := req.Header.Get("Padding") != ""
	if padded {
		resp += "Padding: " + PaddingHeader() + "\r\n"
	}
	resp += "\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		return nil, err
	}
	userID := 0
	if user != nil {
		userID = user.ID
	}
	var data net.Conn = &replayConn{Conn: conn, r: br}
	if padded {
		data = &paddingConn{Conn: data}
	}
	return &core.Session{
		UserID: userID,
		Dest:   dest,
		Conn:   data,
		Socket: tcpConn(conn),
	}, nil
}

// PaddingHeader is naive.PaddingHeader @0xad4ca0: a 30..61 character visible
// string, the first 16 characters drawn from the 16-byte table, the remainder
// filled with '~'.
func PaddingHeader() string {
	n := 0x1e + randN(0x20) // 30..61
	p := make([]byte, n)
	seed := randomSeed()
	for i := 0; i < 16 && i < n; i++ {
		p[i] = paddingChars[seed&0xf]
		seed >>= 4
	}
	for i := 16; i < n; i++ {
		p[i] = '~'
	}
	return string(p)
}

// Destination resolves a CONNECT authority (naive.destination @0xad4ba0).
func Destination(authority string) (socks.Addr, error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return socks.Addr{}, ErrNoAuthority
	}
	// naive.destination @0xad4ba0 splits host:port and compares the host with the
	// two UDP-over-TCP pseudo names (gated on a leading '0' byte in the binary)
	// before falling through to httpproxy.ParseDest. Both paths end in ParseDest
	// here: the pseudo names carry a port like any other destination, and callers
	// that care can ask IsUDPOverTCP.
	return httpproxy.ParseDest(authority)
}

// IsUDPOverTCP reports whether host is one of the two naive UDP-over-TCP pseudo
// destinations.
func IsUDPOverTCP(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	return h == udpOverTCPv2 || h == udpOverTCP
}

// WriteDecoyResponse writes the decoy 101 page (the naive package's own decoy:
// the head literal @0xf96186 plus a small page carrying DecoyMarker).
func WriteDecoyResponse(w io.Writer) error {
	_, err := io.WriteString(w, decoyHead+time.Now().UTC().Format(http.TimeFormat)+"\r\n"+
		"Connection: upgrade\r\nUpgrade: websocket\r\nContent-Type: text/html\r\n\r\n"+
		"<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head>"+
		"<body><h1>Welcome to nginx!</h1>"+DecoyMarker+"</body></html>")
	return err
}

// Looks reports whether a connection's first bytes look like an HTTP CONNECT
// request, which is what the sniffer needs before handing the connection here.
func Looks(head []byte) bool {
	return len(head) >= 8 && strings.HasPrefix(strings.ToUpper(string(head[:8])), "CONNECT ")
}

// --- helpers -------------------------------------------------------------

func randN(n int) int {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n))
}

func randomSeed() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b[:])
}

func readHead(r *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	for {
		line, err := r.ReadSlice('\n')
		out = append(out, line...)
		if len(out) > max {
			return nil, errHeadTooLarge
		}
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			return nil, err
		}
		if len(line) == 2 && line[0] == '\r' || len(line) == 1 && line[0] == '\n' {
			return out, nil
		}
	}
}

var errHeadTooLarge = errors.New("naive: request head too large")

// replayConn serves the buffered bytes first, then the connection.
type replayConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *replayConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func tcpConn(c net.Conn) *net.TCPConn {
	if tc, ok := c.(*net.TCPConn); ok {
		return tc
	}
	return nil
}
