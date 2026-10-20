package outbound

import (
	"context"
	"errors"
	"fmt"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// xudpPacket opens a VLESS command-2 stream and frames datagrams with kaze's
// own XUDP layout (REPORT.md §17.3.1; outbound.(*xudpPacket) @0xb83e20).
// Vision refuses plain UDP ("vless outbound: Vision does not carry plain UDP"),
// so a flow-enabled outbound has to use udp_over_tcp instead.
func (p *Proxy) xudpPacket(ctx context.Context, dest socks.Addr) (core.PacketStream, error) {
	if p.flow != "" {
		return nil, fmt.Errorf("vless outbound: Vision does not carry plain UDP; set udp_over_tcp=true to carry it as a stream")
	}
	c, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := p.vlessRequest(c, dest, vlessCmdUDP); err != nil {
		c.Close()
		return nil, err
	}
	return newXUDPPacket(&vlessRespConn{Conn: c}), nil
}

// uotPacket carries datagrams as UDP-over-TCP v2 frames over the protocol's
// normal TCP stream (notes/rev-ops.md §2.3: the third UDP carriage).
func (p *Proxy) uotPacket(ctx context.Context, dest socks.Addr) (core.PacketStream, error) {
	c, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	switch p.protocol {
	case "vless":
		if err := p.vlessRequest(c, dest, vlessCmdTCP); err != nil {
			c.Close()
			return nil, err
		}
		c = &vlessRespConn{Conn: c}
	case "vmess":
		c, err = p.vmessStream(c, dest)
		if err != nil {
			c.Close()
			return nil, err
		}
	case "trojan":
		c, err = p.trojanStream(c, dest)
		if err != nil {
			c.Close()
			return nil, err
		}
	default:
		c.Close()
		return nil, errors.New("outbound: udp_over_tcp is not implemented for this protocol")
	}
	return newUoTPacket(c, dest), nil
}
