package transport

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// Minimal ClientHello reader used by REALITY. Evidence: the sample parses the
// first TLS record itself before authenticateAt: strings "not a ClientHello",
// "not a TLS handshake", "reality: unexpected record in the handshake",
// "reality: record too long", "unable to read session id",
// "unable to read key share extension data" (notes/rev-transport.md §3.2,
// §3.6).

const (
	recordTypeHandshake = 0x16
	curveX25519         = 0x001d
	extensionServerName = 0
	extensionALPN       = 16
	extensionKeyShare   = 51
)

var errNotTLS = errors.New("first record does not look like a TLS handshake")

type keyShare struct {
	group uint16
	data  []byte
}

// clientHello is the subset of the ClientHello REALITY authenticates.
type clientHello struct {
	random     []byte
	sessionID  []byte
	serverName string
	alpn       []string
	keyShare   *keyShare
}

// readClientHello reads TLS handshake records until the full first handshake
// message is available. It returns the handshake message (starting with the
// handshake type byte) and every record byte it consumed, so an accepted
// connection can be replayed into crypto/tls and a refused one can be
// forwarded to the borrowed site unchanged.
func readClientHello(c net.Conn) (msg, records []byte, err error) {
	var buf []byte
	var hdr [5]byte
	for {
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return nil, records, err
		}
		if hdr[0] != recordTypeHandshake {
			return nil, records, errNotTLS
		}
		n := int(binary.BigEndian.Uint16(hdr[3:5]))
		if n == 0 || n > 1<<15 {
			return nil, records, errors.New("reality: record too long")
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c, payload); err != nil {
			return nil, records, err
		}
		records = append(records, hdr[:]...)
		records = append(records, payload...)
		buf = append(buf, payload...)
		if len(buf) < 4 {
			continue
		}
		want := 4 + int(buf[1])<<16 + int(buf[2])<<8 + int(buf[3])
		if len(buf) >= want {
			return buf[:want], records, nil
		}
	}
}

// parseClientHello decodes the fields REALITY needs.
func parseClientHello(raw []byte) (*clientHello, error) {
	if len(raw) < 4 || raw[0] != 0x01 {
		return nil, errors.New("reality: not a ClientHello")
	}
	body := raw[4:]
	if len(body) < 2+32+1 {
		return nil, errors.New("reality: not a TLS handshake")
	}
	h := &clientHello{}
	body = body[2:] // legacy_version
	h.random = append([]byte(nil), body[:32]...)
	body = body[32:]
	sidLen := int(body[0])
	body = body[1:]
	if sidLen > 32 || len(body) < sidLen {
		return nil, errors.New("unable to read session id")
	}
	h.sessionID = append([]byte(nil), body[:sidLen]...)
	body = body[sidLen:]
	if len(body) < 2 {
		return nil, errors.New("reality: not a TLS handshake")
	}
	csLen := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	if len(body) < csLen+1 {
		return nil, errors.New("reality: not a TLS handshake")
	}
	body = body[csLen:]
	cmLen := int(body[0])
	body = body[1:]
	if len(body) < cmLen {
		return nil, errors.New("reality: not a TLS handshake")
	}
	body = body[cmLen:]
	if len(body) < 2 {
		return h, nil // no extensions
	}
	extLen := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	if len(body) < extLen {
		return nil, errors.New("reality: not a TLS handshake")
	}
	body = body[:extLen]
	for len(body) >= 4 {
		typ := binary.BigEndian.Uint16(body[:2])
		l := int(binary.BigEndian.Uint16(body[2:4]))
		body = body[4:]
		if len(body) < l {
			return nil, errors.New("reality: not a TLS handshake")
		}
		data := body[:l]
		body = body[l:]
		switch typ {
		case extensionServerName:
			if len(data) < 2 {
				continue
			}
			listLen := int(binary.BigEndian.Uint16(data[:2]))
			list := data[2:]
			if listLen > len(list) {
				listLen = len(list)
			}
			list = list[:listLen]
			for len(list) >= 3 {
				nt := list[0]
				nl := int(binary.BigEndian.Uint16(list[1:3]))
				list = list[3:]
				if nl > len(list) {
					break
				}
				if nt == 0 {
					h.serverName = string(list[:nl])
				}
				list = list[nl:]
			}
		case extensionALPN:
			if len(data) < 2 {
				continue
			}
			listLen := int(binary.BigEndian.Uint16(data[:2]))
			list := data[2:]
			if listLen > len(list) {
				listLen = len(list)
			}
			list = list[:listLen]
			for len(list) >= 1 {
				nl := int(list[0])
				list = list[1:]
				if nl > len(list) {
					break
				}
				h.alpn = append(h.alpn, string(list[:nl]))
				list = list[nl:]
			}
		case extensionKeyShare:
			if len(data) < 2 {
				continue
			}
			listLen := int(binary.BigEndian.Uint16(data[:2]))
			list := data[2:]
			if listLen > len(list) {
				listLen = len(list)
			}
			list = list[:listLen]
			for len(list) >= 4 {
				group := binary.BigEndian.Uint16(list[:2])
				kl := int(binary.BigEndian.Uint16(list[2:4]))
				list = list[4:]
				if kl > len(list) {
					break
				}
				if h.keyShare == nil && (group == curveX25519 || group == 0x11ec) {
					key := list[:kl]
					// X25519MLKEM768 is mlkem-encapsulation-key || x25519-share.
					if group == 0x11ec && len(key) > 32 {
						key = key[len(key)-32:]
					}
					if len(key) == 32 {
						h.keyShare = &keyShare{group: curveX25519, data: append([]byte(nil), key...)}
					}
				}
				list = list[kl:]
			}
		}
	}
	return h, nil
}

// negotiateProto picks the ALPN protocol to serve when REALITY terminates TLS.
func negotiateProto(offered []string) string {
	for _, p := range offered {
		switch p {
		case "h2", "http/1.1":
			return p
		}
	}
	return ""
}
