package hysteria

import (
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"

	"github.com/ANRCM0/TX-Node/internal/dataplane/congestion/bbr"
	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
)

// statusAuthOK is the authentication success status (0xe9 = 233). Evidence:
// (*client).ServeHTTP @0xaa2ce0 ends with w.WriteHeader(233)
// (notes/rev-proto-udp.md §1.2).
const statusAuthOK = 233

// Header names, character-for-character from the binary:
// "Hysteria-Auth" @0xf5ecb6 (13 B), "Hysteria-CC-RX" @0xf5fb16 (14 B),
// "Hysteria-UDP" and "Hysteria-Padding" @0xf61ccf (notes §1.2, §1.5).
const (
	headerAuth     = "Hysteria-Auth"
	headerCCRX     = "Hysteria-CC-RX"
	headerUDP      = "Hysteria-UDP"
	headerPadding  = "Hysteria-Padding"
	authHost       = "hysteria"
	authPath       = "/auth"
	notFoundBody   = "404 page not found"
	notFoundStatus = http.StatusNotFound
)

// frameTypeHeaders is the HTTP/3 HEADERS frame type. Streams that do not start
// with it are hysteria data-plane streams, not HTTP requests.
const frameTypeHeaders http3.FrameType = 0x1

// connState is the per-connection authentication state. The binary keeps it in
// the (*client) value the http3 handler closes over: +0x10 mu, +0x18 authed,
// +0x20 user (notes §1.2).
type connState struct {
	srv  *Server
	conn *quic.Conn

	mu        sync.Mutex
	authed    bool
	user      core.User
	userValid *atomic.Bool

	sessMu    sync.Mutex
	sessions  map[uint32]*udpSession
	datagrams sync.Once
	sweepAt   time.Time
}

// dispatchStream is http3.Server.StreamDispatcher: the first varint of every
// bidirectional stream is peeked. A HEADERS frame means an HTTP/3 request (the
// auth POST), anything else is a hysteria request stream, which the server takes
// over. This replaces the sample's StreamHijacker (see the package comment).
func (st *connState) dispatchStream(ft http3.FrameType, str *quic.Stream, err error) (bool, error) {
	if err != nil {
		// The stream could not even be peeked; refuse it without letting the
		// HTTP/3 layer report a protocol error on the connection.
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestIncomplete))
		str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestIncomplete))
		return true, nil
	}
	if ft == frameTypeHeaders {
		return false, nil
	}
	st.mu.Lock()
	authed := st.authed && st.userValid != nil && st.userValid.Load()
	st.mu.Unlock()
	if !authed {
		// Before /auth succeeds the connection has no data plane. Dropping the
		// stream keeps the failure indistinguishable from a closed connection.
		str.CancelRead(quic.StreamErrorCode(0))
		str.CancelWrite(quic.StreamErrorCode(0))
		return true, nil
	}
	go st.handleStream(str)
	return true, nil
}

// authHandler answers POST /auth. Any mismatch — wrong method, wrong authority,
// wrong path, unknown token — produces the identical 404 page, which is the
// sample's active-probing defence (notes/rev-proto-udp.md §1.2: "失败与路径不对
// 同一响应").
type authHandler struct{ srv *Server }

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Host != authHost || r.URL.Path != authPath {
		h.notFound(w)
		return
	}
	st, _ := r.Context().Value(connStateKey{}).(*connState)
	if st == nil {
		h.notFound(w)
		return
	}
	h.srv.authAttempts.Add(1)

	token := r.Header.Get(headerAuth)
	st.mu.Lock()
	if !st.authed {
		h.srv.usersMu.RLock()
		u, ok := h.srv.users[token]
		valid := h.srv.credentialValidity[token]
		h.srv.usersMu.RUnlock()
		if !ok {
			st.mu.Unlock()
			h.srv.authFailures.Add(1)
			h.notFound(w)
			return
		}
		st.authed = true
		st.user = u
		st.userValid = valid
	}
	if st.userValid == nil || !st.userValid.Load() {
		st.mu.Unlock()
		h.notFound(w)
		return
	}
	user := st.user
	st.mu.Unlock()

	// Client receive rate, clamped by the node's own up bandwidth (cfg+0x18).
	rx := parseCCRX(r.Header.Get(headerCCRX))
	if up := h.srv.upBytesPerSec; up > 0 && rx > up {
		rx = up
	}
	if st.conn != nil {
		if rx > 0 && !h.srv.autoCC {
			// brutal: fixed-rate congestion control, tx = rx bytes/s, gain 1.0.
			installBrutal(st.conn, rx)
		} else {
			bbr.UseProfile(st.conn, h.srv.opts.Profile)
		}
	}

	// Headers, in the order the binary sets them.
	w.Header().Set(headerUDP, "true")
	if h.srv.autoCC {
		w.Header().Set(headerCCRX, "auto")
	} else {
		w.Header().Set(headerCCRX, strconv.FormatInt(h.srv.ccRX(), 10))
	}
	w.Header().Set(headerPadding, padding(paddingMin, paddingMax))
	w.WriteHeader(statusAuthOK)

	// The sample starts its forwarding goroutine here (go forward_loop()). The
	// data-plane streams are dispatched by dispatchStream; what is left to start
	// is the QUIC-datagram reader for UDP sessions.
	st.startDatagramLoop()
	remote := ""
	if st.conn != nil {
		remote = st.conn.RemoteAddr().String()
	}
	h.srv.log.Debug("hysteria: authenticated", "user", user.ID, "remote", remote, "rx", rx)
}

// ccRX is the receive bandwidth the server advertises back to the client
// (cfg+0x20), in bytes per second.
func (s *Server) ccRX() int64 { return s.upBytesPerSec }

// userID returns the authenticated user id under the state mutex.
func (st *connState) userIDValue() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.user.ID
}

func (st *connState) authValid() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.authed && st.userValid != nil && st.userValid.Load()
}

func (h *authHandler) notFound(w http.ResponseWriter) {
	http.Error(w, notFoundBody, notFoundStatus)
}

// parseCCRX parses the client's receive rate. A malformed value behaves like an
// absent one (ParseUint's error is discarded by the binary's flow).
func parseCCRX(v string) int64 {
	if v == "" {
		return 0
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0
	}
	return int64(n)
}
