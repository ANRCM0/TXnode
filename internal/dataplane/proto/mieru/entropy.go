package mieru

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	v2ProtoLowC2S = 10
	v2ProtoLowS2C = 11
)

var errEntropy = errors.New("mieru: invalid low entropy record")

func entropySourceBytes(mode entropyMode) (int, error) {
	if mode < 1 || mode > 4 {
		return 0, errEntropy
	}
	return int(mode) + 3, nil
}

func entropySize(length int, mode entropyMode) (int, error) {
	width, err := entropySourceBytes(mode)
	if err != nil || length <= 0 || length > v2MaxPayload {
		return 0, errEntropy
	}
	n := ((length + width - 1) / width) * 8
	if n > 65535 {
		return 0, errEntropy
	}
	return n, nil
}

func entropyMask(mask uint32, mode entropyMode, rotation entropyRotation, index int) (uint64, error) {
	width, err := entropySourceBytes(mode)
	if err != nil || bits.OnesCount32(mask) != width*4 || (rotation > 15 && (rotation%16 != 0 || rotation > 240)) {
		return 0, errEntropy
	}
	full := uint64(mask)<<32 | uint64(mask)
	shift := -int(rotation)
	if rotation > 15 {
		shift = int(rotation) / 16
	}
	return bits.RotateLeft64(full, shift*(index%64)), nil
}

func entropyHalfMask(mode entropyMode) (uint32, error) {
	width, err := entropySourceBytes(mode)
	if err != nil {
		return 0, err
	}
	var mask uint32
	// Draw distinct bit positions. The fixed 32-bit domain bounds all storage;
	// rejection does not bias the set of available positions.
	positions := [32]byte{}
	for i := range positions {
		positions[i] = byte(i)
	}
	for i := 0; i < width*4; i++ {
		offset, err := randomBound(31 - i)
		if err != nil {
			return 0, err
		}
		j := i + offset
		positions[i], positions[j] = positions[j], positions[i]
		mask |= uint32(1) << positions[i]
	}
	return mask, nil
}

// scatterBits / gatherBits implement the wire format's least-significant-bit
// deposit and extract, independent of CPU-specific PDEP/PEXT instructions.
func scatterBits(value, mask uint64) uint64 {
	var out uint64
	for mask != 0 {
		bit := mask & -mask
		if value&1 != 0 {
			out |= bit
		}
		value >>= 1
		mask &= mask - 1
	}
	return out
}

func gatherBits(value, mask uint64) uint64 {
	var out uint64
	var index uint
	for mask != 0 {
		bit := mask & -mask
		if value&bit != 0 {
			out |= uint64(1) << index
		}
		index++
		mask &= mask - 1
	}
	return out
}

func entropyEncode(body []byte, mode entropyMode, mask uint32, rotation entropyRotation, paddingBit byte) ([]byte, error) {
	length, err := entropySize(len(body), mode)
	if err != nil || paddingBit > 1 {
		return nil, errEntropy
	}
	width, _ := entropySourceBytes(mode)
	out := make([]byte, length)
	for offset, chunk := 0, 0; offset < len(body); offset, chunk = offset+width, chunk+1 {
		n := min(width, len(body)-offset)
		m, err := entropyMask(mask, mode, rotation, chunk)
		if err != nil {
			return nil, err
		}
		var scratch [8]byte
		copy(scratch[8-n:], body[offset:offset+n])
		dataMask := scatterBits((uint64(1)<<(n*8))-1, m)
		value := scatterBits(binary.BigEndian.Uint64(scratch[:]), m)
		if paddingBit != 0 {
			value |= ^dataMask
		}
		binary.BigEndian.PutUint64(out[chunk*8:], value)
	}
	return out, nil
}

func entropyDecode(body []byte, extracted int, mode entropyMode, mask uint32, rotation entropyRotation) ([]byte, error) {
	length, err := entropySize(extracted, mode)
	if err != nil || len(body) != length {
		return nil, errEntropy
	}
	width, _ := entropySourceBytes(mode)
	out := make([]byte, extracted)
	var polarity bool
	for offset, chunk := 0, 0; offset < extracted; offset, chunk = offset+width, chunk+1 {
		n := min(width, extracted-offset)
		m, err := entropyMask(mask, mode, rotation, chunk)
		if err != nil {
			return nil, err
		}
		value := binary.BigEndian.Uint64(body[chunk*8:])
		dataMask := scatterBits((uint64(1)<<(n*8))-1, m)
		padMask := ^dataMask
		pad := value & padMask
		if chunk == 0 {
			polarity = pad == padMask
		}
		if (polarity && pad != padMask) || (!polarity && pad != 0) {
			return nil, errEntropy
		}
		var scratch [8]byte
		binary.BigEndian.PutUint64(scratch[:], gatherBits(value, m))
		copy(out[offset:offset+n], scratch[8-n:])
	}
	return out, nil
}

func entropyMetadata(meta []byte, mode entropyMode, rotation entropyRotation, length int) error {
	encoded, err := entropySize(length, mode)
	if err != nil {
		return err
	}
	mask, err := entropyHalfMask(mode)
	if err != nil {
		return err
	}
	meta[1] = byte(mode)
	binary.BigEndian.PutUint16(meta[22:24], uint16(encoded))
	binary.BigEndian.PutUint32(meta[25:29], mask)
	binary.BigEndian.PutUint16(meta[29:31], uint16(length))
	meta[31] = byte(rotation)
	return nil
}

func entropySealPayload(sealed, meta []byte) ([]byte, error) {
	length := int(binary.BigEndian.Uint16(meta[29:31]))
	if len(sealed) != length+v2TagLen {
		return nil, errEntropy
	}
	var bit [1]byte
	if _, err := rand.Read(bit[:]); err != nil {
		return nil, err
	}
	body, err := entropyEncode(sealed[:length], entropyMode(meta[1]), binary.BigEndian.Uint32(meta[25:29]), entropyRotation(meta[31]), bit[0]&1)
	if err != nil {
		return nil, err
	}
	return append(body, sealed[length:]...), nil
}

func entropyOpenPayload(wire, meta []byte) ([]byte, error) {
	length := int(binary.BigEndian.Uint16(meta[22:24]))
	extracted := int(binary.BigEndian.Uint16(meta[29:31]))
	if len(wire) != length+v2TagLen || length == 0 {
		return nil, errEntropy
	}
	body, err := entropyDecode(wire[:length], extracted, entropyMode(meta[1]), binary.BigEndian.Uint32(meta[25:29]), entropyRotation(meta[31]))
	if err != nil {
		return nil, err
	}
	return append(body, wire[length:]...), nil
}
