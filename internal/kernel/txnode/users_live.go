package txnode

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/mieru"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/shadowsocks"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/snell"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/socks5"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/vless"
	"github.com/ANRCM0/TX-Node/internal/dataplane/proto/vmess"
)

var errCredentialsChanged = errors.New("credentials changed during handshake")

type liveHandlerState struct {
	handler     core.Handler
	security    core.Handler
	credentials map[int]*liveCredential
}

type liveCredential struct {
	uuid  string
	valid atomic.Bool
}

// liveHandler publishes immutable credentials while transports keep one stable
// handler. Updates are serialized by Kernel.mu; handshakes never take that lock.
type liveHandler struct {
	sp               *spec
	log              *slog.Logger
	state            atomic.Pointer[liveHandlerState]
	configure        func(core.Handler)
	packetOwner      atomic.Pointer[shadowsocks.Handler]
	mieruPacketOwner atomic.Pointer[mieru.Handler]
}

func newLiveHandler(sp *spec, users []core.User, log *slog.Logger) (*liveHandler, error) {
	h := &liveHandler{sp: sp, log: log}
	if err := h.SetUsers(users); err != nil {
		return nil, err
	}
	if len(users) == 0 && (sp.Protocol == "shadowsocks" || sp.Protocol == "socks5" || sp.Protocol == "mieru") {
		owner, err := buildHandler(sp, nil, log)
		if err != nil {
			return nil, err
		}
		h.state.Store(&liveHandlerState{handler: denyUserHandler{}, security: owner})
	}
	return h, nil
}

func (h *liveHandler) Current() core.Handler { return h.state.Load().handler }

func (h *liveHandler) PacketCapable() bool {
	_, ok := h.state.Load().security.(core.PacketHandler)
	return ok
}

// Inherit retains replay state across a node reload. A new VLESS encryption
// configuration must build its own ticket/key owner.
func (h *liveHandler) Inherit(previous *liveHandler) {
	if previous == nil || h.sp.Protocol != previous.sp.Protocol {
		return
	}
	if h.sp.Protocol == "vless" && h.sp.Decryption != previous.sp.Decryption {
		return
	}
	next, old := h.state.Load(), previous.state.Load()
	if old.security == nil {
		return
	}
	if next.security == nil {
		h.state.Store(&liveHandlerState{handler: next.handler, security: old.security, credentials: next.credentials})
		return
	}
	inheritSecurityState(next.security, old.security)
}

// Retire invalidates pending handshakes and new streams on a draining runtime.
func (h *liveHandler) Retire() {
	old := h.state.Load()
	for _, credential := range old.credentials {
		credential.valid.Store(false)
	}
	h.state.Store(&liveHandlerState{handler: denyUserHandler{}, security: old.security})
	if owner := h.packetOwner.Load(); owner != nil {
		owner.ClosePackets()
	}
	if owner := h.mieruPacketOwner.Load(); owner != nil {
		owner.ClosePackets()
	}
}

// Configure installs listener-specific relay callbacks on each replacement.
// It is called before the runtime is published.
func (h *liveHandler) Configure(fn func(core.Handler)) {
	h.configure = fn
	if fn != nil {
		fn(h.Current())
		state := h.state.Load()
		if state.security != nil && state.security != state.handler {
			fn(state.security)
		}
	}
}

func (h *liveHandler) SetUsers(users []core.User) error {
	old := h.state.Load()
	next := &liveHandlerState{handler: denyUserHandler{}}
	if old != nil {
		next.security = old.security
	}
	if len(users) > 0 {
		built, err := buildHandler(h.sp, users, h.log)
		if err != nil {
			return err
		}
		if next.security != nil {
			inheritSecurityState(built, next.security)
		}
		next.handler, next.security = built, built
		if h.configure != nil {
			h.configure(built)
		}
	}
	next.credentials = make(map[int]*liveCredential, len(users))
	for _, user := range users {
		if user.ID <= 0 {
			continue
		}
		if old != nil {
			if credential := old.credentials[user.ID]; credential != nil && credential.uuid == user.UUID && credential.valid.Load() {
				next.credentials[user.ID] = credential
				continue
			}
		}
		credential := &liveCredential{uuid: user.UUID}
		credential.valid.Store(true)
		next.credentials[user.ID] = credential
	}
	if old != nil {
		for id, credential := range old.credentials {
			if next.credentials[id] != credential {
				credential.valid.Store(false)
			}
		}
	}
	h.state.Store(next)
	if owner := h.packetOwner.Load(); owner != nil {
		owner.ClosePackets()
	}
	if owner := h.mieruPacketOwner.Load(); owner != nil {
		owner.ClosePackets()
	}
	return nil
}

func inheritSecurityState(next, previous core.Handler) {
	switch n := next.(type) {
	case *vmess.Handler:
		if p, ok := previous.(*vmess.Handler); ok {
			n.InheritSecurityState(p)
		}
	case *shadowsocks.Handler:
		if p, ok := previous.(*shadowsocks.Handler); ok {
			n.InheritSecurityState(p)
		}
	case *snell.Handler:
		if p, ok := previous.(*snell.Handler); ok {
			n.InheritSecurityState(p)
		}
	case *socks5.Handler:
		if p, ok := previous.(*socks5.Handler); ok {
			n.InheritPacketState(p)
		}
	case *mieru.Handler:
		if p, ok := previous.(*mieru.Handler); ok {
			n.InheritSecurityState(p)
		}
	case *vless.Handler:
		if p, ok := previous.(*vless.Handler); ok {
			n.InheritSecurityState(p)
		}
	}
}

func (h *liveHandler) Handle(ctx context.Context, conn net.Conn) (*core.Session, error) {
	state := h.state.Load()
	if mh, ok := state.security.(*mieru.Handler); ok {
		mh.SetCurrent(func() *mieru.Handler {
			current, _ := h.Current().(*mieru.Handler)
			return current
		})
	}
	sess, err := state.handler.Handle(ctx, conn)
	if err != nil {
		return sess, err
	}
	var credential *liveCredential
	if sess != nil && sess.UserID > 0 {
		credential = state.credentials[sess.UserID]
	}
	valid := func() bool { return credential != nil && credential.valid.Load() }
	if !valid() {
		if sess != nil {
			if sess.Conn != nil {
				_ = sess.Conn.Close()
			}
			if sess.Packets != nil {
				_ = sess.Packets.Close()
			}
		}
		return nil, errCredentialsChanged
	}
	if sess != nil {
		sess.AuthValid = valid
	}
	return sess, nil
}

func (h *liveHandler) ServePackets(ctx context.Context, pc net.PacketConn) error {
	owner, ok := h.state.Load().security.(core.PacketHandler)
	if !ok {
		return errors.New("protocol has no native packet handler")
	}
	if ss, ok := owner.(*shadowsocks.Handler); ok {
		ss.SetCurrent(func() *shadowsocks.Handler {
			current, _ := h.Current().(*shadowsocks.Handler)
			return current
		})
		h.packetOwner.Store(ss)
	}
	if mh, ok := owner.(*mieru.Handler); ok {
		mh.SetCurrent(func() *mieru.Handler {
			current, _ := h.Current().(*mieru.Handler)
			return current
		})
		h.mieruPacketOwner.Store(mh)
	}
	return owner.ServePackets(ctx, pc)
}

type denyUserHandler struct{}

func (denyUserHandler) Handle(context.Context, net.Conn) (*core.Session, error) {
	return nil, errors.New("no users admitted")
}
