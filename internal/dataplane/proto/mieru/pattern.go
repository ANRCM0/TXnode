package mieru

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// TrafficPattern accepts the v3.38.1 trafficPattern fields carried by the panel.
// Empty input retains the original defaults; seed/unlockAll opt into generation.
type TrafficPattern struct {
	Seed        *int32          `json:"seed,omitempty"`
	UnlockAll   *bool           `json:"unlockAll,omitempty"`
	TCPFragment *TCPFragment    `json:"tcpFragment,omitempty"`
	Nonce       *NoncePattern   `json:"nonce,omitempty"`
	Padding     *PaddingPattern `json:"padding,omitempty"`
	LowEntropy  *EntropyPattern `json:"lowEntropy,omitempty"`
}

type TCPFragment struct {
	Enable     bool `json:"enable,omitempty"`
	MaxSleepMS *int `json:"maxSleepMs,omitempty"`
}

type NoncePattern struct {
	Type                nonceType `json:"type,omitempty"`
	ApplyToAllUDPPacket bool      `json:"applyToAllUDPPacket,omitempty"`
	MinLen              *int      `json:"minLen,omitempty"`
	MaxLen              *int      `json:"maxLen,omitempty"`
	CustomHexStrings    []string  `json:"customHexStrings,omitempty"`
}

type PaddingPattern struct {
	MaxMiddle *int `json:"maxMiddlePaddingLen,omitempty"`
	MaxEnd    *int `json:"maxEndPaddingLen,omitempty"`
}

type EntropyPattern struct {
	Mode         entropyMode     `json:"mode,omitempty"`
	MaskRotation entropyRotation `json:"maskRotation,omitempty"`
}

type nonceType byte
type entropyMode byte
type entropyRotation byte

func enumValue(raw []byte, prefix string, names map[string]byte) (byte, error) {
	var name string
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &name); err != nil {
			return 0, err
		}
		if value, ok := names[strings.TrimPrefix(name, prefix)]; ok {
			return value, nil
		}
		return 0, fmt.Errorf("mieru: unknown enum %q", name)
	}
	n, err := strconv.ParseUint(string(raw), 10, 8)
	if err != nil {
		return 0, fmt.Errorf("mieru: invalid enum %s", raw)
	}
	for _, value := range names {
		if byte(n) == value {
			return byte(n), nil
		}
	}
	return 0, fmt.Errorf("mieru: unknown enum %d", n)
}

func (v *nonceType) UnmarshalJSON(raw []byte) error {
	n, err := enumValue(raw, "NONCE_TYPE_", map[string]byte{"RANDOM": 0, "PRINTABLE": 1, "PRINTABLE_SUBSET": 2, "FIXED": 3})
	*v = nonceType(n)
	return err
}
func (v *entropyMode) UnmarshalJSON(raw []byte) error {
	n, err := enumValue(raw, "LOW_ENTROPY_MODE_", map[string]byte{"OFF": 0, "32": 1, "40": 2, "48": 3, "56": 4})
	*v = entropyMode(n)
	return err
}
func (v *entropyRotation) UnmarshalJSON(raw []byte) error {
	names := map[string]byte{"NO_ROTATION": 0}
	for i := 1; i <= 15; i++ {
		names["ROTATE_RIGHT_"+strconv.Itoa(i)] = byte(i)
		names["ROTATE_LEFT_"+strconv.Itoa(i)] = byte(i * 16)
	}
	n, err := enumValue(raw, "LOW_ENTROPY_MASK_", names)
	*v = entropyRotation(n)
	return err
}

func ValidateTrafficPattern(raw string) error {
	_, err := parseTrafficPattern(raw)
	return err
}

func parseTrafficPattern(raw string) (*TrafficPattern, error) {
	p := &TrafficPattern{}
	if strings.TrimSpace(raw) == "" {
		return p, nil
	}
	if !strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return nil, errors.New("mieru: traffic_pattern must be a JSON object")
	}
	if len(raw) > 16<<10 {
		return nil, errors.New("mieru: traffic_pattern exceeds 16 KiB")
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(p); err != nil {
		return nil, fmt.Errorf("mieru: traffic_pattern must be explicit trafficPattern JSON: %w", err)
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return nil, errors.New("mieru: trailing traffic_pattern JSON")
	}
	if f := p.TCPFragment; f != nil && f.MaxSleepMS != nil && (*f.MaxSleepMS < 0 || *f.MaxSleepMS > 100) {
		return nil, errors.New("mieru: tcpFragment.maxSleepMs must be in [0,100]")
	}
	if n := p.Nonce; n != nil {
		for _, length := range []*int{n.MinLen, n.MaxLen} {
			if length != nil && (*length < 0 || *length > 12) {
				return nil, errors.New("mieru: nonce lengths must be in [0,12]")
			}
		}
		if n.MinLen != nil && n.MaxLen != nil && *n.MinLen > *n.MaxLen {
			return nil, errors.New("mieru: nonce minLen exceeds maxLen")
		}
		if len(n.CustomHexStrings) > 64 {
			return nil, errors.New("mieru: too many nonce prefixes")
		}
		for _, prefix := range n.CustomHexStrings {
			b, err := hex.DecodeString(prefix)
			if err != nil || len(b) > 12 {
				return nil, errors.New("mieru: invalid nonce customHexStrings prefix")
			}
		}
	}
	if p.Padding != nil {
		for _, length := range []*int{p.Padding.MaxMiddle, p.Padding.MaxEnd} {
			if length != nil && (*length < 0 || *length > 255) {
				return nil, errors.New("mieru: padding lengths must be in [0,255]")
			}
		}
	}
	if p.Seed != nil || (p.UnlockAll != nil && *p.UnlockAll) {
		if err := p.resolveSeed(raw); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func randomBound(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	// Reject the incomplete modulo bucket to keep every configured length fair.
	limit := 256 - 256%(max+1)
	var b [1]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		if int(b[0]) < limit {
			return int(b[0]) % (max + 1), nil
		}
	}
}

func (p *TrafficPattern) padding(max int, middle bool) ([]byte, error) {
	if max > 255 {
		max = 255
	}
	if p != nil && p.Padding != nil {
		length := p.Padding.MaxEnd
		if middle {
			length = p.Padding.MaxMiddle
		}
		if length != nil && max > *length {
			max = *length
		}
	}
	// Empty configuration retains the original inbound's no-padding behavior.
	if p == nil || p.Padding == nil {
		return nil, nil
	}
	n, err := randomBound(max)
	if err != nil {
		return nil, err
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	for i := range b {
		b[i] = 0x20 + b[i]%95
	}
	return b, nil
}

func (p *TrafficPattern) nonce(nonce []byte, first bool) error {
	if p == nil || p.Nonce == nil || (!first && !p.Nonce.ApplyToAllUDPPacket) {
		return nil
	}
	n := p.Nonce
	if n.Type == 0 {
		return nil
	}
	if n.Type == 3 {
		if len(n.CustomHexStrings) == 0 {
			return nil
		}
		i, err := randomBound(len(n.CustomHexStrings) - 1)
		if err != nil {
			return err
		}
		prefix, _ := hex.DecodeString(n.CustomHexStrings[i])
		copy(nonce, prefix)
		return nil
	}
	minLen, maxLen := 0, 12
	if n.MinLen != nil {
		minLen = *n.MinLen
	}
	if n.MaxLen != nil {
		maxLen = *n.MaxLen
	}
	if minLen > maxLen {
		return errors.New("mieru: effective nonce minimum exceeds maximum")
	}
	length, err := randomBound(maxLen - minLen)
	if err != nil {
		return err
	}
	length += minLen
	const subset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := 0; i < length; i++ {
		if n.Type == 1 {
			nonce[i] = 0x20 + nonce[i]%95
		} else {
			nonce[i] = subset[int(nonce[i])%len(subset)]
		}
	}
	return nil
}

func (p *TrafficPattern) writeTCP(conn io.Writer, out []byte) error {
	if p == nil || p.TCPFragment == nil || !p.TCPFragment.Enable || len(out) < 2 {
		return writeFull(conn, out)
	}
	// At most two transport writes per record; protocol fragment boundaries stay
	// independent of TCP packetization and never create another business write.
	split, err := randomBound(min(len(out)-2, 254))
	if err != nil {
		return err
	}
	split++
	if err := writeFull(conn, out[:split]); err != nil {
		return err
	}
	maxSleep := 10
	if p.TCPFragment.MaxSleepMS != nil {
		maxSleep = *p.TCPFragment.MaxSleepMS
	}
	delay, err := randomBound(maxSleep)
	if err != nil {
		return err
	}
	if delay > 0 {
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}
	return writeFull(conn, out[split:])
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
