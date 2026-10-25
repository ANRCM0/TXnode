package mieru

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// The field domains and 31-bit SHA-256 mapping follow the pinned v3.38.1
// trafficPattern configuration contract. No upstream runtime is linked here.
func patternNumber(hint string, count int) int {
	digest := sha256.Sum256([]byte(hint))
	return int(binary.BigEndian.Uint32(digest[:4])&0x7fffffff) % count
}

func patternFields(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil, nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("mieru: traffic pattern component must be an object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, errors.New("mieru: invalid traffic pattern key")
		}
		name = strings.ToLower(name)
		if _, exists := fields[name]; exists {
			return nil, errors.New("mieru: duplicate implicit traffic pattern field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	return fields, nil
}

func (p *TrafficPattern) resolveSeed(raw string) error {
	object, err := patternFields(json.RawMessage(raw))
	if err != nil {
		return err
	}
	fields := make(map[string]map[string]json.RawMessage, 4)
	for _, section := range []string{"tcpFragment", "nonce", "padding", "lowEntropy"} {
		component, err := patternFields(object[strings.ToLower(section)])
		if err != nil {
			return err
		}
		fields[section] = component
	}
	present := func(section, name string) bool {
		value, exists := fields[section][strings.ToLower(name)]
		return exists && strings.TrimSpace(string(value)) != "null"
	}
	seed := int32(0)
	if p.Seed != nil {
		seed = *p.Seed
	} else {
		host, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("mieru: traffic pattern host seed: %w", err)
		}
		seed = int32(patternNumber(host+" 3.38.1", 1<<31-1))
	}
	pick := func(field string, count int) int {
		return patternNumber(fmt.Sprintf("%d:%s", seed, field), count)
	}
	integer := func(value int) *int { return &value }
	unlock := p.UnlockAll != nil && *p.UnlockAll
	if p.TCPFragment == nil {
		p.TCPFragment = &TCPFragment{}
	}
	if !present("tcpFragment", "enable") {
		p.TCPFragment.Enable = unlock && pick("tcpFragment.enable", 2) == 1
	}
	if !present("tcpFragment", "maxSleepMs") {
		value := 0
		if unlock {
			value = pick("tcpFragment.maxSleepMs", 100) + 1
		}
		p.TCPFragment.MaxSleepMS = integer(value)
	}
	if p.Nonce == nil {
		p.Nonce = &NoncePattern{}
	}
	if !present("nonce", "type") {
		p.Nonce.Type = nonceType(pick("nonce.type", 2) + 1)
		if unlock {
			p.Nonce.Type = nonceType(pick("nonce.type", 3))
		}
	}
	if !present("nonce", "applyToAllUDPPacket") {
		p.Nonce.ApplyToAllUDPPacket = pick("nonce.applyToAllUDPPacket", 2) == 1
	}
	if !present("nonce", "minLen") {
		value := pick("nonce.minLen", 7) + 6
		if unlock {
			value = pick("nonce.minLen", 13)
		}
		p.Nonce.MinLen = integer(value)
	}
	if !present("nonce", "maxLen") {
		p.Nonce.MaxLen = integer(*p.Nonce.MinLen + pick("nonce.maxLen", 13-*p.Nonce.MinLen))
	}
	if *p.Nonce.MinLen > *p.Nonce.MaxLen {
		return errors.New("mieru: generated nonce minimum exceeds explicit maximum")
	}
	if p.Padding == nil {
		p.Padding = &PaddingPattern{}
	}
	if !present("padding", "maxMiddlePaddingLen") {
		p.Padding.MaxMiddle = integer(max(0, pick("padding.maxMiddlePaddingLen", 256)-128))
	}
	if !present("padding", "maxEndPaddingLen") {
		value := 255
		if unlock {
			value = pick("padding.maxEndPaddingLen", 256)
		}
		p.Padding.MaxEnd = integer(value)
	}
	if p.LowEntropy == nil {
		p.LowEntropy = &EntropyPattern{}
	}
	if !present("lowEntropy", "mode") {
		p.LowEntropy.Mode = 0
		if unlock {
			p.LowEntropy.Mode = entropyMode(pick("lowEntropy.mode", 5))
		}
	}
	if !present("lowEntropy", "maskRotation") {
		rotation := pick("lowEntropy.maskRotation", 31)
		if rotation > 15 {
			rotation = (rotation - 15) * 16
		}
		p.LowEntropy.MaskRotation = entropyRotation(rotation)
	}
	return nil
}
