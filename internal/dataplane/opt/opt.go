// Package opt is the outbound option reader observed at opt.Opt (rev-round2-core
// §17.2.3): a map[string]any whose Str looks up several candidate keys and
// stringifies whatever type it finds. It is only used by outbound stream and
// plugin options; inbound protocol handlers never read it.
package opt

import (
	"fmt"
	"strconv"
	"strings"
)

// Opt is a zero-cost alias of map[string]any, exactly as the binary's
// opt.Opt (rtype 0xef1140) is structurally identical to map[string]interface{}.
type Opt map[string]any

// Str returns the first present key rendered as a string. Strings are returned
// as-is, integers via FormatInt, float64 via FormatFloat('f', -1, 64); other
// types render with fmt.Sprint so boolean/JSON options still work.
func (o Opt) Str(keys ...string) string {
	for _, k := range keys {
		v, ok := o[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			return t
		case int:
			return strconv.FormatInt(int64(t), 10)
		case int64:
			return strconv.FormatInt(t, 10)
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(t)
		default:
			return fmt.Sprint(t)
		}
	}
	return ""
}

// Bool parses a boolean option, accepting the spellings the panels use.
func (o Opt) Bool(keys ...string) bool {
	s := strings.ToLower(strings.TrimSpace(o.Str(keys...)))
	switch s {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Int parses an integer option.
func (o Opt) Int(keys ...string) int {
	s := strings.TrimSpace(o.Str(keys...))
	n, _ := strconv.Atoi(s)
	return n
}

// Any returns the raw value for a candidate key.
func (o Opt) Any(keys ...string) (any, bool) {
	for _, k := range keys {
		if v, ok := o[k]; ok {
			return v, true
		}
	}
	return nil, false
}

// Map returns a nested object as Opt.
func (o Opt) Map(keys ...string) Opt {
	if v, ok := o.Any(keys...); ok {
		if m, ok := v.(map[string]any); ok {
			return Opt(m)
		}
	}
	return nil
}

// Merge returns a copy of o with src's keys merged in (later wins), matching
// node.mergeStream's shallow copy + key merge (rev-round3-outbound §19.3).
func Merge(dst, src Opt) Opt {
	out := make(Opt, len(dst)+len(src))
	for k, v := range dst {
		out[k] = v
	}
	for k, v := range src {
		out[k] = v
	}
	return out
}
