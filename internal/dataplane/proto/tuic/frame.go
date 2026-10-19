// Package tuic implements the TUIC v5 inbound server of kaze.
//
// Evidence: kazecore/notes/rev-proto-udp.md §2 (tuic) and REPORT.md §6.7. The
// binary's package has 40 functions; the stream demultiplexing
// ((*client).run @0xb41900, (*client).uniStream @0xb41ee0, (*client).connect
// @0xb42d00, (*client).packet @0xb43860), the authentication command
// (0xb4217b), the dissociate command (0xb42009), the udp session frame builder
// ((*udpSession).frame @0xb44a00) and the write path
// ((*udpSession).WritePacket @0xb44c60) are read instruction by instruction.
package tuic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/ANRCM0/TX-Node/internal/dataplane/socks"
)

// Wire constants.
const (
	// version is the only accepted protocol version: uniStream returns when
	// buf[0] != 5 (0xb41fc4).
	version = 5
	// Command bytes on unidirectional streams. There is no cmd == 1 on a uni
	// stream; CONNECT travels on a bidirectional stream.
	cmdAuthenticate = 0
	cmdPacket       = 2
	cmdDissociate   = 3
	// cmdConnect is the bidirectional-stream command.
	cmdConnect = 1
	// authLen is the fixed Authenticate body: UUID (16 B) then token (32 B)
	// ("mov edi,0x30" @0xb4219a).
	authLen = 48
	// uuidLen is the UUID prefix length.
	uuidLen = 16
	// tokenLen is the token length.
	tokenLen = 32
	// frameHeaderLen is the fixed part of the packet frame: VER(1) CMD(1)
	// ASSOC_ID(2) PKT_ID(2) FRAG_ID(1) FRAG_TOTAL(1) LEN(2).
	frameHeaderLen = 10
	// fragOverhead is the per-fragment space reserved by the fragmentation
	// path: the report's split uses (errLen - 0x1d), 0x1d = 29 = 10-byte frame
	// header + the largest address encoding (IPv6: 1+16+2 = 19). It is the
	// worst-case frame overhead, not the actual one.
	fragOverhead = 0x1d
	// maxFragments bounds a fragmented datagram (fragTotal is a u8).
	maxFragments = 0xff
	// addrNone marks a frame without an address (appendAddr writes 0xff).
	addrNone = 0xff
)

// TUIC address types differ from SOCKS5: 1 is a domain, 3 is IPv4 and 4 is IPv6
// (readAddr @0xb42580 / appendAddr @0xb42900, notes §2.3).
const (
	addrDomain = 1
	addrIPv4   = 3
	addrIPv6   = 4
)

// Header is the 2-byte stream prefix: version and command. The sample writes it
// with a single "mov word [rax],0x205" (0xb44a65) for a v5 Packet frame.
type Header struct {
	Version uint8
	Command uint8
}

// Append appends the 2-byte header.
func (h Header) Append(buf []byte) []byte {
	return append(buf, h.Version, h.Command)
}

// frame is one TUIC v5 packet frame:
//
//	05 02 | assocID(2) | pktID(2) | fragID(1) | fragTotal(1) | len(2) | addr? | payload
//
// len is the payload length; the address is self-describing. On the wire the
// address follows the header and the payload follows the address, which is how
// (*udpSession).frame @0xb44a00 builds it (buf[0]=0x05, buf[1]=0x02 @0xb44a65,
// buf[10] = address or 0xff @0xb44b73/0xb44b8f, payload after).
type frame struct {
	assocID   uint16
	pktID     uint16
	fragID    uint8
	fragTotal uint8
	addr      socks.Addr
	hasAddr   bool
	payload   []byte
}

// headerSize is the full frame size before the payload.
func (f *frame) headerSize() int {
	n := frameHeaderLen
	if f.hasAddr {
		n += encodedAddrLen(f.addr)
	} else {
		n++
	}
	return n
}

// append serialises the frame into buf.
func (f *frame) append(buf []byte) []byte {
	buf = append(buf, version, cmdPacket)
	buf = binary.BigEndian.AppendUint16(buf, f.assocID)
	buf = binary.BigEndian.AppendUint16(buf, f.pktID)
	buf = append(buf, f.fragID, f.fragTotal)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(f.payload)))
	if f.hasAddr {
		buf = appendAddr(buf, f.addr)
	} else {
		buf = append(buf, addrNone)
	}
	buf = append(buf, f.payload...)
	return buf
}

// marshal serialises the frame into a fresh slice.
func (f *frame) marshal() []byte { return f.append(make([]byte, 0, f.headerSize()+len(f.payload))) }

// errShortFrame is returned when a stream carries fewer bytes than the frame
// announces.
var errShortFrame = errors.New("tuic: short packet frame")

// parsePacketBody parses the 8 bytes after VER/CMD on a client Packet command,
// then the address and the payload. Evidence: (*client).packet @0xb43860 reads
// assocID(2 BE), u16, u8, u8, len(2 BE), payload, address (notes §2.3 records
// the offsets; the named FRAG semantics are inferred).
func parsePacketBody(b []byte) (*frame, error) {
	if len(b) < 8 {
		return nil, errShortFrame
	}
	f := &frame{
		assocID:   binary.BigEndian.Uint16(b[0:2]),
		pktID:     binary.BigEndian.Uint16(b[2:4]),
		fragID:    b[4],
		fragTotal: b[5],
	}
	payloadLen := int(binary.BigEndian.Uint16(b[6:8]))
	rest := b[8:]
	// The address sits between the header and the payload. 0xff means none.
	if len(rest) > 0 && rest[0] != addrNone && rest[0] != 0 {
		addr, n, err := readAddr(rest)
		if err != nil {
			return nil, err
		}
		f.addr = addr
		f.hasAddr = true
		rest = rest[n:]
	} else if len(rest) > 0 {
		rest = rest[1:]
	}
	if len(rest) < payloadLen {
		return nil, errShortFrame
	}
	f.payload = rest[:payloadLen]
	return f, nil
}

// appendAddr encodes an address with TUIC's type numbers.
func appendAddr(buf []byte, a socks.Addr) []byte {
	if ip := a.IP(); ip.IsValid() {
		if ip.Is4() {
			v4 := ip.As4()
			buf = append(buf, addrIPv4)
			buf = append(buf, v4[:]...)
			return binary.BigEndian.AppendUint16(buf, a.Port)
		}
		v6 := ip.As16()
		buf = append(buf, addrIPv6)
		buf = append(buf, v6[:]...)
		return binary.BigEndian.AppendUint16(buf, a.Port)
	}
	buf = append(buf, addrDomain, byte(len(a.Host)))
	buf = append(buf, a.Host...)
	return binary.BigEndian.AppendUint16(buf, a.Port)
}

// encodedAddrLen is appendAddr's output length.
func encodedAddrLen(a socks.Addr) int {
	if ip := a.IP(); ip.IsValid() {
		if ip.Is4() {
			return 1 + 4 + 2
		}
		return 1 + 16 + 2
	}
	return 1 + 1 + len(a.Host) + 2
}

// readAddr parses an address and returns it with the number of bytes consumed.
func readAddr(b []byte) (socks.Addr, int, error) {
	if len(b) < 1 {
		return socks.Addr{}, 0, errors.New("tuic: empty address")
	}
	switch b[0] {
	case addrDomain:
		if len(b) < 2 {
			return socks.Addr{}, 0, errors.New("tuic: short domain address")
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return socks.Addr{}, 0, errors.New("tuic: truncated domain address")
		}
		return socks.Addr{Host: string(b[2 : 2+l]), Port: binary.BigEndian.Uint16(b[2+l : 2+l+2])}, 2 + l + 2, nil
	case addrIPv4:
		if len(b) < 1+4+2 {
			return socks.Addr{}, 0, errors.New("tuic: short IPv4 address")
		}
		return socks.Addr{Host: net.IP(b[1:5]).String(), Port: binary.BigEndian.Uint16(b[5:7])}, 7, nil
	case addrIPv6:
		if len(b) < 1+16+2 {
			return socks.Addr{}, 0, errors.New("tuic: short IPv6 address")
		}
		return socks.Addr{Host: net.IP(b[1:17]).String(), Port: binary.BigEndian.Uint16(b[17:19])}, 19, nil
	case 0, addrNone:
		return socks.Addr{}, 1, nil
	}
	return socks.Addr{}, 0, fmt.Errorf("tuic: unknown address type %d", b[0])
}

// fragChunkSize is the payload size used when a datagram does not fit:
// (errLen - 0x1d), the split the report records at 0xb44db8–0xb44df8.
func fragChunkSize(maxDatagramPayload int) int {
	n := maxDatagramPayload - fragOverhead
	if n <= 0 {
		return 1
	}
	return n
}

// fragment splits payload into chunks of at most chunk bytes, returning the
// frames with fragID/fragTotal filled in. fragTotal is capped at 0xff: the field
// cannot express more (0xb44df2).
func fragment(base *frame, payload []byte, chunk int) []*frame {
	if chunk <= 0 {
		chunk = 1
	}
	if len(payload) <= chunk {
		f := *base
		f.payload = payload
		f.fragID, f.fragTotal = 0, 0
		return []*frame{&f}
	}
	total := (len(payload) + chunk - 1) / chunk
	clipped := false
	if total > maxFragments {
		total = maxFragments
		clipped = true
	}
	out := make([]*frame, 0, total)
	for i := 0; i < total; i++ {
		start := i * chunk
		end := start + chunk
		if end > len(payload) {
			end = len(payload)
		}
		f := *base
		f.fragID = uint8(i)
		f.fragTotal = uint8(total)
		f.payload = payload[start:end]
		out = append(out, &f)
		if end == len(payload) {
			break
		}
	}
	if clipped && len(out) > 0 {
		// Keep the frame count legal; the last fragment carries the remainder so
		// no byte is silently dropped.
		last := out[len(out)-1]
		start := (len(out) - 1) * chunk
		last.payload = payload[start:]
	}
	return out
}
