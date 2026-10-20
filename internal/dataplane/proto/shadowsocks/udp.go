package shadowsocks

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// ServePackets decrypts client datagrams and hands authenticated packet streams
// to the common relay, which owns routing, admission, limits and accounting.
func (h *Handler) ServePackets(ctx context.Context, pc net.PacketConn) error {
	if !h.udp {
		return errors.New("shadowsocks: UDP is not available on this node")
	}
	if h.relay == nil {
		return errors.New("shadowsocks: UDP relay is not configured")
	}
	srv := &udpServer{h: h, pc: pc, ctx: ctx, sess: make(map[string]*udpSession)}
	defer srv.closeSessions()
	h.pkt.Store(srv)
	defer h.pkt.CompareAndSwap(srv, nil)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = pc.Close()
		case <-stop:
		}
	}()

	buf := make([]byte, 0x10000)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		srv.handle(from, buf[:n])
	}
}

// udpServer is ss.(*PacketServer).
type udpServer struct {
	h      *Handler
	active *Handler
	ctx    context.Context
	pc     net.PacketConn
	mu     sync.Mutex
	sess   map[string]*udpSession
}

func (s *udpServer) handle(from net.Addr, datagram []byte) {
	handler := s.h.currentHandler()
	if handler != s.active {
		s.closeSessions()
		s.active = handler
	}
	if handler == nil {
		return
	}
	dest, payload, us, err := handler.openUDP(datagram)
	if err != nil || us.user == nil || us.user.ID <= 0 {
		return
	}
	key := fmt.Sprintf("%s/%d/%x/%d", from.String(), us.user.ID, us.key, us.sessID)
	s.mu.Lock()
	sess := s.sess[key]
	if sess == nil {
		sessionCtx, cancel := context.WithCancel(s.ctx)
		sess = &udpSession{srv: s, client: from, us: us, key: key, ctx: sessionCtx, cancel: cancel, done: make(chan struct{}), incoming: make(chan udpPacket, 64)}
		sess.touch()
		s.sess[key] = sess
		go sess.expire()
		go func() {
			defer sess.Close()
			host, _, _ := net.SplitHostPort(from.String())
			source, _ := netip.ParseAddr(host)
			_ = handler.relay(sess.ctx, &core.Session{UserID: us.user.ID, Packets: sess, SourceIP: source, AuthValid: func() bool { return s.h.currentHandler() == handler }})
		}()
	}
	s.mu.Unlock()
	packet := udpPacket{dest: dest, payload: append([]byte(nil), payload...)}
	select {
	case <-sess.done:
		return
	default:
	}
	select {
	case sess.incoming <- packet:
		sess.touch()
	default:
	}
}

func (s *udpServer) closeSessions() {
	s.mu.Lock()
	sessions := make([]*udpSession, 0, len(s.sess))
	for _, sess := range s.sess {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	for _, sess := range sessions {
		_ = sess.Close()
	}
}

// udpKeyState carries what the reply direction needs: the key material and the
// 2022 session id.
type udpKeyState struct {
	key    []byte
	user   *core.User
	is2022 bool
	sessID uint64
}

// openUDP decrypts one datagram and returns its destination plus payload
// (ss.(*PacketServer).handleClassic / handle2022).
func (h *Handler) openUDP(datagram []byte) (socks.Addr, []byte, *udpKeyState, error) {
	if h.spec.kind == kind2022 {
		return h.openUDP2022(datagram)
	}
	if len(datagram) < h.spec.saltSize+2+16 {
		return socks.Addr{}, nil, nil, errAuth
	}
	salt := datagram[:h.spec.saltSize]
	if !h.salts.add(salt) {
		return socks.Addr{}, nil, nil, ErrReplayedSalt
	}
	body := datagram[h.spec.saltSize:]
	peer := "" // no per-peer state on this path; the table below is enough
	candidates := h.search.order(peer, len(h.users))
	for _, idx := range candidates {
		uk := &h.users[idx]
		aead, err := h.classicAEAD(uk.key, salt)
		if err != nil {
			continue
		}
		nonce := newNonceCounter(aead.NonceSize())
		plain, err := aead.Open(nil, nonce.get(), body, nil)
		if err != nil {
			continue
		}
		dest, n, err := ReadAddrFrom(plain)
		if err != nil {
			return socks.Addr{}, nil, nil, err
		}
		return dest, plain[n:], &udpKeyState{key: uk.key, user: uk.user}, nil
	}
	if len(h.serverKey) > 0 {
		aead, err := h.classicAEAD(h.serverKey, salt)
		if err == nil {
			nonce := newNonceCounter(aead.NonceSize())
			if plain, err := aead.Open(nil, nonce.get(), body, nil); err == nil {
				dest, n, err := ReadAddrFrom(plain)
				if err != nil {
					return socks.Addr{}, nil, nil, err
				}
				return dest, plain[n:], &udpKeyState{key: h.serverKey}, nil
			}
		}
	}
	return socks.Addr{}, nil, nil, errAuth
}

// openUDP2022 decrypts a SIP022 datagram:
//
//	session id (8) | packet id (8) | salt (keySize) | AEAD(type, timestamp, addr, payload)
//
// UNVERIFIED: the exact datagram layout; the binary only exposes the function
// names (open2022/write2022/udpKey) and REPORT.md §24.1 shows the 2022 path failing
// even kaze↔kaze.
func (h *Handler) openUDP2022(datagram []byte) (socks.Addr, []byte, *udpKeyState, error) {
	head := 16 + h.spec.saltSize
	if len(datagram) < head+1+8+16 {
		return socks.Addr{}, nil, nil, errAuth
	}
	sessID := binary.BigEndian.Uint64(datagram[0:8])
	packetID := binary.BigEndian.Uint64(datagram[8:16])
	salt := datagram[16 : 16+h.spec.saltSize]
	if !h.salts.add(salt) {
		return socks.Addr{}, nil, nil, ErrReplayedSalt
	}
	body := datagram[head:]

	keys := make([][]byte, 0, len(h.users)+1)
	users := make([]*core.User, 0, len(h.users)+1)
	for i := range h.users {
		keys = append(keys, h.users[i].key)
		users = append(users, h.users[i].user)
	}
	if len(h.serverKey) > 0 {
		keys = append(keys, h.serverKey)
		users = append(users, nil)
	}
	for i, key := range keys {
		subkey := sessionSubkey(key, salt, h.spec.keySize)
		aead, err := h.spec.newAEAD(subkey)
		if err != nil {
			continue
		}
		nonce := nonceForPacket(aead.NonceSize(), packetID)
		plain, err := aead.Open(nil, nonce, body, nil)
		if err != nil {
			continue
		}
		if len(plain) < 9 || plain[0] != headerClientStream {
			continue
		}
		ts := int64(binary.BigEndian.Uint64(plain[1:9]))
		if !h.checkTimestamp(ts) {
			return socks.Addr{}, nil, nil, errTimestamp
		}
		dest, n, err := ReadAddrFrom(plain[9:])
		if err != nil {
			return socks.Addr{}, nil, nil, err
		}
		return dest, plain[9+n:], &udpKeyState{key: key, user: users[i], is2022: true, sessID: sessID}, nil
	}
	return socks.Addr{}, nil, nil, errAuth
}

// udpSession is one authenticated client endpoint bridged to the common relay.
type udpSession struct {
	srv      *udpServer
	client   net.Addr
	us       *udpKeyState
	key      string
	ctx      context.Context
	cancel   context.CancelFunc
	writeMu  sync.Mutex
	once     sync.Once
	last     atomic.Int64
	done     chan struct{}
	incoming chan udpPacket
	packet   atomic.Uint64
}

type udpPacket struct {
	dest    socks.Addr
	payload []byte
}

func (s *udpSession) RemoteAddr() net.Addr { return s.client }

func (s *udpSession) ReadPacket(p []byte) (int, socks.Addr, error) {
	select {
	case <-s.done:
		return 0, socks.Addr{}, net.ErrClosed
	default:
	}
	select {
	case <-s.done:
		return 0, socks.Addr{}, net.ErrClosed
	case pkt := <-s.incoming:
		select {
		case <-s.done:
			return 0, socks.Addr{}, net.ErrClosed
		default:
		}
		if len(p) < len(pkt.payload) {
			return 0, socks.Addr{}, io.ErrShortBuffer
		}
		return copy(p, pkt.payload), pkt.dest, nil
	}
}

func (s *udpSession) WritePacket(p []byte, dest socks.Addr) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	reply, err := s.srv.h.sealUDP(dest, p, s.us, s)
	if err != nil {
		return err
	}
	n, err := s.srv.pc.WriteTo(reply, s.client)
	if err == nil && n != len(reply) {
		err = io.ErrShortWrite
	}
	if err == nil {
		s.touch()
	}
	return err
}

func (s *udpSession) touch() { s.last.Store(time.Now().UnixNano()) }

func (s *udpSession) expire() {
	t := time.NewTicker(udpIdle / 4)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			if time.Since(time.Unix(0, s.last.Load())) > udpIdle {
				_ = s.Close()
				return
			}
		}
	}
}

// sealUDP encrypts one reply datagram.
func (h *Handler) sealUDP(dest socks.Addr, payload []byte, us *udpKeyState, sess *udpSession) ([]byte, error) {
	plain := make([]byte, 0, addrLen(dest)+len(payload)+9)
	if h.spec.kind == kind2022 {
		var head [9]byte
		head[0] = headerServerStream
		binary.BigEndian.PutUint64(head[1:], uint64(nowUnix()))
		plain = append(plain, head[:]...)
	}
	plain = appendAddr(plain, dest)
	plain = append(plain, payload...)

	salt := make([]byte, h.spec.saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	var (
		aead interface {
			Seal(dst, nonce, plaintext, additionalData []byte) []byte
			NonceSize() int
		}
		nonce []byte
	)
	if h.spec.kind == kind2022 {
		subkey := sessionSubkey(us.key, salt, h.spec.keySize)
		a, err := h.spec.newAEAD(subkey)
		if err != nil {
			return nil, err
		}
		aead, nonce = a, nonceForPacket(a.NonceSize(), sess.packet.Add(1))
	} else {
		a, err := h.classicAEAD(us.key, salt)
		if err != nil {
			return nil, err
		}
		aead, nonce = a, newNonceCounter(a.NonceSize()).get()
	}
	out := make([]byte, 0, 16+h.spec.saltSize+len(plain)+16)
	if h.spec.kind == kind2022 {
		out = binary.BigEndian.AppendUint64(out, us.sessID)
		out = binary.BigEndian.AppendUint64(out, sess.packet.Load())
	}
	out = append(out, salt...)
	return aead.Seal(out, nonce, plain, nil), nil
}

// Close tears the session down (ss.(*udpSession).Close).
func (s *udpSession) Close() error {
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		s.writeMu.Lock()
		close(s.done)
		s.writeMu.Unlock()

		s.srv.mu.Lock()
		if s.srv.sess[s.key] == s {
			delete(s.srv.sess, s.key)
		}
		s.srv.mu.Unlock()
	})
	return nil
}

// nonceForPacket builds the SIP022 UDP nonce from a packet id.
func nonceForPacket(size int, id uint64) []byte {
	n := make([]byte, size)
	binary.LittleEndian.PutUint64(n, id)
	return n
}

var _ core.PacketStream = (*udpSession)(nil)
