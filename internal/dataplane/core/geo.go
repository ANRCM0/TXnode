package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
)

// This file reconstructs the hand-written protobuf reader used for the v2ray
// geoip.dat / geosite.dat databases (REPORT.md §8.2):
//
//	pbField  @0x7a10e0   read one protobuf field
//	pbWalk   @0x7a1200   iterate every field of a message
//	geoEntry @0x7a1720   decode one GeoIP / GeoSite entry
//	Rule.addGeoSite @0x7a1f00 / Rule.addGeoIP @0x7a2780
//	LoadBlockListGeo @0x7ae260
//
// The wire format is the standard v2ray one:
//
//	GeoSiteList { repeated GeoSite entry = 1; }
//	GeoSite     { string country_code = 1; repeated Domain domain = 2; }
//	Domain      { Type type = 1; string value = 2; }   Type: Plain=0 Regex=1 Domain=2 Full=3
//	GeoIPList   { repeated GeoIP entry = 1; }
//	GeoIP       { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3; }
//	CIDR        { bytes ip = 1; uint32 prefix = 2; }
//
// Field numbers and the damage message ("geo data file %s is damaged (an entry
// claims %d bytes)") are the ones observed in the binary's string pool; the
// per-field tag walk itself is a reconstruction marked UNVERIFIED below.

// geoDomain is one compiled domain entry of a geosite list.
type geoDomain struct {
	Full    string
	Suffix  string
	Keyword string
	Regexp  *regexp.Regexp
}

// Geo is one parsed geo data file. Both tables are always present because the
// original uses the same decoder for geoip.dat and geosite.dat.
type Geo struct {
	Path  string
	Sites map[string][]geoDomain    // upper-case country/tag code -> domains
	IPs   map[string][]netip.Prefix // upper-case country code -> prefixes
}

var (
	geoMu    sync.RWMutex
	geoSites = map[string][]geoDomain{}
	geoIPs   = map[string][]netip.Prefix{}
)

// SetGeo installs parsed tables as the process-wide source for geosite:/geoip:
// match terms. The binary keeps a single registry next to the rule builder
// (prepareRouter calls LoadBlockListGeo before building rules), so the same
// process-wide model is used here.
func SetGeo(g *Geo) {
	if g == nil {
		return
	}
	geoMu.Lock()
	defer geoMu.Unlock()
	for k, v := range g.Sites {
		geoSites[strings.ToUpper(k)] = v
	}
	for k, v := range g.IPs {
		geoIPs[strings.ToUpper(k)] = v
	}
}

// LoadGeo reads and decodes one geoip.dat / geosite.dat file. The format is
// inferred from the first entry: a field-1 varint is a geosite Domain, a
// field-1 byte string is a geoip CIDR. Loaded entries are also installed in the
// process-wide registry so AddMatch("geosite:...") can use them.
func LoadGeo(path string) (*Geo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	g := &Geo{Path: path, Sites: map[string][]geoDomain{}, IPs: map[string][]netip.Prefix{}}
	err = pbWalk(data, func(num int, wire int, val []byte) error {
		if num != 1 || wire != 2 {
			return nil
		}
		ent, err := parseGeoEntry(data, path, val)
		if err != nil {
			return err
		}
		if ent.Code == "" {
			return nil
		}
		key := strings.ToUpper(ent.Code)
		if len(ent.Domains) > 0 {
			g.Sites[key] = append(g.Sites[key], ent.Domains...)
		}
		if len(ent.Prefixes) > 0 {
			g.IPs[key] = append(g.IPs[key], ent.Prefixes...)
		}
		return nil
	})
	if err != nil {
		var le *pbLengthError
		if errors.As(err, &le) {
			return nil, fmt.Errorf("geo data file %s is damaged (an entry claims %d bytes)", path, le.claim)
		}
		return nil, err
	}
	SetGeo(g)
	return g, nil
}

// pbLengthError reports a length-delimited field whose claimed length runs past
// the end of its message. LoadGeo turns it into the binary's damage message.
type pbLengthError struct{ claim uint64 }

func (e *pbLengthError) Error() string { return "malformed protobuf" }

// pbField reads one field of a protobuf message. It returns the field number,
// wire type, the raw value (varint value, fixed bytes, or length-delimited
// payload) and the remaining bytes. (core.pbField @0x7a10e0)
func pbField(b []byte) (num int, wire int, val []byte, rest []byte, err error) {
	key, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, 0, nil, nil, fmt.Errorf("malformed protobuf")
	}
	num = int(key >> 3)
	wire = int(key & 7)
	b = b[n:]
	if num <= 0 {
		return 0, 0, nil, nil, fmt.Errorf("malformed protobuf")
	}
	switch wire {
	case 0: // varint
		v, m := binary.Uvarint(b)
		if m <= 0 {
			return 0, 0, nil, nil, fmt.Errorf("malformed protobuf")
		}
		var tmp [binary.MaxVarintLen64]byte
		nn := binary.PutUvarint(tmp[:], v)
		return num, wire, tmp[:nn], b[m:], nil
	case 1: // fixed64
		if len(b) < 8 {
			return 0, 0, nil, nil, fmt.Errorf("malformed protobuf")
		}
		return num, wire, b[:8], b[8:], nil
	case 2: // length-delimited
		l, m := binary.Uvarint(b)
		if m <= 0 {
			return 0, 0, nil, nil, fmt.Errorf("malformed protobuf")
		}
		b = b[m:]
		if l > uint64(len(b)) {
			return 0, 0, nil, nil, &pbLengthError{claim: l}
		}
		return num, wire, b[:l], b[l:], nil
	case 5: // fixed32
		if len(b) < 4 {
			return 0, 0, nil, nil, fmt.Errorf("malformed protobuf")
		}
		return num, wire, b[:4], b[4:], nil
	default:
		return 0, 0, nil, nil, fmt.Errorf("unsupported protobuf wire type %d", wire)
	}
}

// pbWalk iterates every field of a message (core.pbWalk @0x7a1200). It passes
// the payload for wire type 2, the re-encoded varint for wire type 0 and the
// fixed-width bytes otherwise.
func pbWalk(b []byte, fn func(num int, wire int, val []byte) error) error {
	for len(b) > 0 {
		num, wire, val, rest, err := pbField(b)
		if err != nil {
			return err
		}
		if err := fn(num, wire, val); err != nil {
			return err
		}
		b = rest
	}
	return nil
}

func pbUvarint(b []byte) (uint64, bool) {
	v, n := binary.Uvarint(b)
	return v, n > 0
}

// geoEntry is one decoded GeoIP/GeoSite entry.
type geoEntry struct {
	Code     string
	Domains  []geoDomain
	Prefixes []netip.Prefix
	Reverse  bool
}

// parseGeoEntry decodes the body of one top-level entry. The damage check uses
// the binary's exact message: "geo data file %s is damaged (an entry claims %d
// bytes)". (core.geoEntry @0x7a1720)
func parseGeoEntry(file []byte, path string, body []byte) (geoEntry, error) {
	var ent geoEntry
	err := pbWalk(body, func(num int, wire int, val []byte) error {
		switch {
		case num == 1 && wire == 2:
			ent.Code = string(val)
		case num == 2 && wire == 2:
			dom, pre, err := parseGeoInner(file, path, val)
			if err != nil {
				return err
			}
			ent.Domains = append(ent.Domains, dom...)
			ent.Prefixes = append(ent.Prefixes, pre...)
		case num == 3 && wire == 0:
			v, _ := pbUvarint(val)
			ent.Reverse = v != 0
		}
		return nil
	})
	if err != nil {
		return geoEntry{}, err
	}
	return ent, nil
}

// parseGeoInner classifies the repeated element of an entry. A Domain starts
// with a varint type field; a CIDR starts with a length-delimited ip field.
func parseGeoInner(file []byte, path string, body []byte) ([]geoDomain, []netip.Prefix, error) {
	// Sniff the first field's wire type.
	firstNum, firstWire, _, _, ferr := pbField(body)
	if ferr != nil {
		return nil, nil, geoDamaged(file, path, body, ferr)
	}
	if firstNum == 1 && firstWire == 0 {
		// geosite Domain
		var typ uint64
		var value string
		err := pbWalk(body, func(num int, wire int, val []byte) error {
			switch {
			case num == 1 && wire == 0:
				typ, _ = pbUvarint(val)
			case num == 2 && wire == 2:
				value = string(val)
			}
			return nil
		})
		if err != nil {
			return nil, nil, geoDamaged(file, path, body, err)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, nil, nil
		}
		switch typ {
		case 0: // Plain
			return []geoDomain{{Keyword: strings.ToLower(value)}}, nil, nil
		case 1: // Regex
			re, err := regexp.Compile(value)
			if err != nil {
				// A malformed expression is not a damaged file; skip the entry.
				return nil, nil, nil
			}
			return []geoDomain{{Regexp: re}}, nil, nil
		case 2: // Domain (suffix)
			return []geoDomain{{Suffix: normDomain(value)}}, nil, nil
		case 3: // Full
			return []geoDomain{{Full: normDomain(value)}}, nil, nil
		}
		return nil, nil, nil
	}
	if firstNum == 1 && firstWire == 2 {
		// geoip CIDR
		var ipBytes []byte
		var bits uint64
		err := pbWalk(body, func(num int, wire int, val []byte) error {
			switch {
			case num == 1 && wire == 2:
				ipBytes = val
			case num == 2 && wire == 0:
				bits, _ = pbUvarint(val)
			}
			return nil
		})
		if err != nil {
			return nil, nil, geoDamaged(file, path, body, err)
		}
		var addr netip.Addr
		switch len(ipBytes) {
		case 4:
			var a [4]byte
			copy(a[:], ipBytes)
			addr = netip.AddrFrom4(a)
		case 16:
			var a [16]byte
			copy(a[:], ipBytes)
			addr = netip.AddrFrom16(a)
		default:
			return nil, nil, nil
		}
		if int(bits) > addr.BitLen() {
			return nil, nil, nil
		}
		return nil, []netip.Prefix{netip.PrefixFrom(addr, int(bits)).Masked()}, nil
	}
	return nil, nil, nil
}

// geoDamaged turns a truncated nested message into the binary's damage message.
func geoDamaged(file []byte, path string, body []byte, err error) error {
	// The claimed length is the number of bytes the outer entry promised but
	// the inner message could not supply.
	claim := len(body)
	_ = file
	return fmt.Errorf("geo data file %s is damaged (an entry claims %d bytes)", path, claim)
}

// addGeoSite implements "geosite:<code>" (core.(*Rule).addGeoSite @0x7a1f00).
func (r *Rule) addGeoSite(code string) error {
	key := strings.ToUpper(strings.TrimSpace(code))
	geoMu.RLock()
	ds, ok := geoSites[key]
	geoMu.RUnlock()
	if !ok || len(ds) == 0 {
		if !geoHasSites() {
			return fmt.Errorf("geosite: data is not loaded (set geosite_file)")
		}
		return fmt.Errorf("geosite:%s matched no domains", code)
	}
	for _, d := range ds {
		switch {
		case d.Full != "":
			if r.fulls == nil {
				r.fulls = make(map[string]struct{})
			}
			r.fulls[d.Full] = struct{}{}
		case d.Suffix != "":
			if r.suffixes == nil {
				r.suffixes = make(map[string]struct{})
			}
			r.suffixes[d.Suffix] = struct{}{}
		case d.Keyword != "":
			r.keywords = append(r.keywords, d.Keyword)
		case d.Regexp != nil:
			r.regexps = append(r.regexps, d.Regexp)
		}
	}
	return nil
}

// addGeoIP implements "geoip:<code>" (core.(*Rule).addGeoIP @0x7a2780).
func (r *Rule) addGeoIP(code string) error {
	key := strings.ToUpper(strings.TrimSpace(code))
	geoMu.RLock()
	ps, ok := geoIPs[key]
	geoMu.RUnlock()
	if !ok || len(ps) == 0 {
		if !geoHasIPs() {
			return fmt.Errorf("geoip: data is not loaded (set geoip_file)")
		}
		return fmt.Errorf("geoip:%s has no address ranges", code)
	}
	for _, p := range ps {
		r.addRange(p)
	}
	return nil
}

func geoHasSites() bool {
	geoMu.RLock()
	defer geoMu.RUnlock()
	return len(geoSites) > 0
}

func geoHasIPs() bool {
	geoMu.RLock()
	defer geoMu.RUnlock()
	return len(geoIPs) > 0
}
