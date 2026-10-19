package core

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// SniffTCP classifies the first bytes of a TCP stream. It returns one of
// "bittorrent", "tls", "http" or "" and, for TLS/HTTP, the requested name
// (SNI or Host). Mirrors core.SniffTCP @0x7b7780.
func SniffTCP(b []byte) (proto, domain string) {
	if len(b) >= 20 && b[0] == 0x13 && bytes.Equal(b[1:20], []byte("BitTorrent protocol")) {
		return "bittorrent", ""
	}
	if name, ok := sniffTLS(b); ok {
		return "tls", name
	}
	if name, ok := sniffHTTP(b); ok {
		return "http", name
	}
	return "", ""
}

// SniffUDP classifies a datagram. The only two results are "bittorrent" and
// "quic" (core.SniffUDP @0x7b7960).
func SniffUDP(b []byte) string {
	// BitTorrent DHT: bencoded "d...e" containing 1:y1:q / 1:y1:r / 1:y1:e.
	if len(b) > 12 && b[0] == 'd' && b[len(b)-1] == 'e' {
		body := b
		if bytes.Contains(body, []byte("1:y1:q")) ||
			bytes.Contains(body, []byte("1:y1:r")) ||
			bytes.Contains(body, []byte("1:y1:e")) {
			return "bittorrent"
		}
	}
	// BitTorrent UDP tracker: protocol id 0x41727101980 then action 0.
	if len(b) >= 16 && binary.BigEndian.Uint64(b[0:8]) == 0x41727101980 && binary.BigEndian.Uint32(b[8:12]) == 0 {
		return "bittorrent"
	}
	// BitTorrent uTP: 20-byte header, version 1, type <= 2.
	if len(b) == 20 && b[0] == 0x41 && b[1] <= 2 {
		return "bittorrent"
	}
	// QUIC Initial: long header, fixed bit, >= 1200 bytes.
	if len(b) >= 1200 && b[0]&0xc0 == 0xc0 {
		version := binary.BigEndian.Uint32(b[1:5])
		typ := (b[0] >> 4) & 3
		switch version {
		case 1, 0xff00001d, 0xff00001c, 0xff000020:
			if typ == 0 {
				return "quic"
			}
		case 0x6b3343cf: // QUIC v2
			if typ == 1 {
				return "quic"
			}
		}
	}
	return ""
}

// sniffTLS parses a TLS ClientHello for the SNI extension. It requires
// b[0]==0x16, major 3, handshake type 1 (client_hello).
func sniffTLS(b []byte) (string, bool) {
	if len(b) < 9 || b[0] != 0x16 || b[1] != 3 || b[5] != 1 {
		return "", false
	}
	// record: type(1) ver(2) len(2); handshake: type(1) len(3)
	if len(b) < 5 {
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen+5 > len(b) {
		recLen = len(b) - 5
	}
	hs := b[5 : 5+recLen]
	if len(hs) < 4+2+32 {
		return "", false
	}
	p := 4 // handshake type + length
	p += 2 // client_version
	if p+32 > len(hs) {
		return "", false
	}
	p += 32 // random
	if p >= len(hs) {
		return "", false
	}
	sidLen := int(hs[p])
	p++
	if p+sidLen+2 > len(hs) {
		return "", false
	}
	p += sidLen
	csLen := int(binary.BigEndian.Uint16(hs[p : p+2]))
	p += 2 + csLen
	if p >= len(hs) {
		return "", false
	}
	cmLen := int(hs[p])
	p++
	p += cmLen
	if p+2 > len(hs) {
		return "", false
	}
	extLen := int(binary.BigEndian.Uint16(hs[p : p+2]))
	p += 2
	end := p + extLen
	if end > len(hs) {
		end = len(hs)
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(hs[p : p+2])
		l := int(binary.BigEndian.Uint16(hs[p+2 : p+4]))
		p += 4
		if p+l > end {
			return "", false
		}
		if typ == 0 { // server_name
			d := hs[p : p+l]
			if len(d) < 5 {
				return "", false
			}
			// list length(2), name type(1), name length(2)
			nl := int(binary.BigEndian.Uint16(d[3:5]))
			if 5+nl > len(d) {
				return "", false
			}
			return strings.ToLower(string(d[5 : 5+nl])), true
		}
		p += l
	}
	return "", false
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
	[]byte("TRACE "),
}

// sniffHTTP looks for a request line and a Host header.
func sniffHTTP(b []byte) (string, bool) {
	ok := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, m) {
			ok = true
			break
		}
	}
	if !ok {
		return "", false
	}
	lineEnd := bytes.Index(b, []byte("\r\n"))
	if lineEnd < 0 {
		return "", false
	}
	head := b[lineEnd+2:]
	for len(head) > 0 {
		i := bytes.Index(head, []byte("\r\n"))
		var line []byte
		if i < 0 {
			line, head = head, nil
		} else {
			line, head = head[:i], head[i+2:]
		}
		if len(line) == 0 {
			break
		}
		if len(line) >= 5 && strings.EqualFold(string(line[:5]), "host:") {
			h := strings.TrimSpace(string(line[5:]))
			h = strings.ToLower(h)
			if strings.HasPrefix(h, "[") {
				if j := strings.IndexByte(h, ']'); j > 0 {
					return h[1:j], true
				}
			}
			if j := strings.LastIndexByte(h, ':'); j > 0 {
				h = h[:j]
			}
			return h, true
		}
	}
	return "", false
}

// RequestedName returns the name a rule should match: the sniffed SNI/Host when
// present, else the destination host (core.requestedName @0x7adb60).
func RequestedName(destHost, sniffed string) string {
	if sniffed != "" {
		return sniffed
	}
	return strings.ToLower(destHost)
}
