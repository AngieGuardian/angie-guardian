// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	challengeRecordVersion       = 1 // legacy/current SHA-256 record
	challengeRecordVersionArgon2 = 2
	challengeRecordStateIssued   = 1
	challengeRecordStateSpent    = 2
	challengeRecordFlagNoJS      = 1 << 0
	challengeRecordKnownFlags    = challengeRecordFlagNoJS
	challengeRecordVersionOffset = 4
	challengeRecordStateOffset   = 5
	challengeRecordFixedSize     = 60
	challengeRecordV2FixedSize   = 84
	challengeRecordMaxFieldSize  = uint64(1<<32 - 1)

	recordStateIssued = "issued"
	recordStateSpent  = "spent"
)

var (
	challengeRecordMagic = [...]byte{'A', 'G', 'C', 'R'}
	errChallengeRecord   = errors.New("invalid challenge record")
)

// record is the compact logical issuance record. ChallengeDigest is the raw
// HMAC digest; its client-facing lowercase hex form is reconstructed only when
// verifying a submitted nonce.
type record struct {
	State           string
	Host            string
	IP              string
	ChallengeDigest [sha256.Size]byte
	Algorithm       Algorithm
	Difficulty      int
	MemoryKiB       uint32
	Iterations      uint32
	Salt            [argon2SaltSize]byte
	URI             string
	NoJS            bool
	IssuedAt        int64 // unix milliseconds
}

func (r *record) proofSpec() ProofSpec {
	return ProofSpec{Algorithm: r.Algorithm, Difficulty: r.Difficulty, MemoryKiB: r.MemoryKiB, Iterations: r.Iterations, Salt: r.Salt}
}

// Compact v1 is deliberately fixed-width through the three length fields:
//
//	magic[4] | version[1] | state[1] | flags[1] | difficulty[1]
//	issued_ms[8] | challenge_digest[32] | host_len[4] | ip_len[4]
//	uri_len[4] | host | ip | uri
//
// Integers are big endian. Length prefixes preserve arbitrary request bytes;
// this is an internal binary record, not UTF-8 text.
//
// encodeChallengeRecord writes that format. The caller owns buf until the Store
// operation returns and may then clear and recycle it.
func encodeChallengeRecord(buf *bytes.Buffer, rec *record) ([]byte, error) {
	if rec.proofSpec().algorithm() == AlgorithmArgon2ID {
		return encodeChallengeRecordV2(buf, rec)
	}
	buf.Reset()
	state, err := binaryRecordState(rec.State)
	if err != nil {
		return nil, err
	}
	if rec.Difficulty < 0 || rec.Difficulty > 255 {
		return nil, fmt.Errorf("%w: difficulty %d is outside uint8", errChallengeRecord, rec.Difficulty)
	}

	host, ip, uri := rec.Host, rec.IP, rec.URI
	if uint64(len(host)) > challengeRecordMaxFieldSize || uint64(len(ip)) > challengeRecordMaxFieldSize || uint64(len(uri)) > challengeRecordMaxFieldSize {
		return nil, fmt.Errorf("%w: host, IP or URI exceeds %d bytes", errChallengeRecord, challengeRecordMaxFieldSize)
	}

	payloadSize := uint64(len(host)) + uint64(len(ip)) + uint64(len(uri))
	maxInt := int(^uint(0) >> 1)
	if payloadSize > uint64(maxInt-challengeRecordFixedSize) {
		return nil, fmt.Errorf("%w: encoded record exceeds platform size", errChallengeRecord)
	}
	total := challengeRecordFixedSize + int(payloadSize)
	buf.Grow(total)
	encoded := buf.AvailableBuffer()
	encoded = append(encoded, challengeRecordMagic[:]...)
	encoded = append(encoded, challengeRecordVersion, state)
	flags := byte(0)
	if rec.NoJS {
		flags |= challengeRecordFlagNoJS
	}
	encoded = append(encoded, flags, byte(rec.Difficulty))
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(rec.IssuedAt))
	encoded = append(encoded, rec.ChallengeDigest[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(host)))
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(ip)))
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(uri)))
	encoded = append(encoded, host...)
	encoded = append(encoded, ip...)
	encoded = append(encoded, uri...)
	if len(encoded) != total {
		return nil, fmt.Errorf("%w: encoded size %d, want %d", errChallengeRecord, len(encoded), total)
	}
	_, _ = buf.Write(encoded)
	return buf.Bytes(), nil
}

func encodeChallengeRecordV2(buf *bytes.Buffer, rec *record) ([]byte, error) {
	buf.Reset()
	state, err := binaryRecordState(rec.State)
	if err != nil {
		return nil, err
	}
	if err := rec.proofSpec().validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", errChallengeRecord, err)
	}
	host, ip, uri := rec.Host, rec.IP, rec.URI
	if uint64(len(host)) > challengeRecordMaxFieldSize || uint64(len(ip)) > challengeRecordMaxFieldSize || uint64(len(uri)) > challengeRecordMaxFieldSize {
		return nil, fmt.Errorf("%w: host, IP or URI exceeds %d bytes", errChallengeRecord, challengeRecordMaxFieldSize)
	}
	payloadSize := uint64(len(host)) + uint64(len(ip)) + uint64(len(uri))
	maxInt := int(^uint(0) >> 1)
	if payloadSize > uint64(maxInt-challengeRecordV2FixedSize) {
		return nil, fmt.Errorf("%w: encoded record exceeds platform size", errChallengeRecord)
	}
	total := challengeRecordV2FixedSize + int(payloadSize)
	buf.Grow(total)
	encoded := buf.AvailableBuffer()
	encoded = append(encoded, challengeRecordMagic[:]...)
	encoded = append(encoded, challengeRecordVersionArgon2, state)
	flags := byte(0)
	if rec.NoJS {
		flags |= challengeRecordFlagNoJS
	}
	encoded = append(encoded, flags, 1, 0, byte(rec.Iterations), 0, 0)
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(rec.IssuedAt))
	encoded = append(encoded, rec.ChallengeDigest[:]...)
	encoded = append(encoded, rec.Salt[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, rec.MemoryKiB)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(host)))
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(ip)))
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(uri)))
	encoded = append(encoded, host...)
	encoded = append(encoded, ip...)
	encoded = append(encoded, uri...)
	if len(encoded) != total {
		return nil, fmt.Errorf("%w: encoded size %d, want %d", errChallengeRecord, len(encoded), total)
	}
	_, _ = buf.Write(encoded)
	return buf.Bytes(), nil
}

func decodeChallengeRecord(raw []byte) (record, error) {
	if len(raw) < len(challengeRecordMagic) || !bytes.Equal(raw[:len(challengeRecordMagic)], challengeRecordMagic[:]) {
		return record{}, fmt.Errorf("%w: compact record magic missing", errChallengeRecord)
	}
	return decodeBinaryChallengeRecord(raw)
}

func decodeBinaryChallengeRecord(raw []byte) (record, error) {
	if len(raw) <= challengeRecordVersionOffset {
		return record{}, fmt.Errorf("%w: truncated version", errChallengeRecord)
	}
	if raw[challengeRecordVersionOffset] == challengeRecordVersionArgon2 {
		return decodeBinaryChallengeRecordV2(raw)
	}
	if raw[challengeRecordVersionOffset] != challengeRecordVersion {
		return record{}, fmt.Errorf("%w: unknown version %d", errChallengeRecord, raw[challengeRecordVersionOffset])
	}
	if len(raw) < challengeRecordFixedSize {
		return record{}, fmt.Errorf("%w: compact record is %d bytes, need at least %d", errChallengeRecord, len(raw), challengeRecordFixedSize)
	}

	state, err := logicalRecordState(raw[challengeRecordStateOffset])
	if err != nil {
		return record{}, err
	}
	flags := raw[6]
	if flags & ^byte(challengeRecordKnownFlags) != 0 {
		return record{}, fmt.Errorf("%w: unknown flags 0x%x", errChallengeRecord, flags)
	}
	hostLen64 := uint64(binary.BigEndian.Uint32(raw[48:52]))
	ipLen64 := uint64(binary.BigEndian.Uint32(raw[52:56]))
	uriLen64 := uint64(binary.BigEndian.Uint32(raw[56:60]))
	if hostLen64+ipLen64+uriLen64 != uint64(len(raw)-challengeRecordFixedSize) {
		return record{}, fmt.Errorf("%w: field lengths do not match record size", errChallengeRecord)
	}
	hostLen, ipLen, uriLen := int(hostLen64), int(ipLen64), int(uriLen64)

	offset := challengeRecordFixedSize
	hostBytes := raw[offset : offset+hostLen]
	offset += hostLen
	ipBytes := raw[offset : offset+ipLen]
	offset += ipLen
	uriBytes := raw[offset : offset+uriLen]
	rec := record{
		State: state, Host: string(hostBytes), IP: string(ipBytes),
		Difficulty: int(raw[7]), URI: string(uriBytes),
		NoJS:     flags&challengeRecordFlagNoJS != 0,
		IssuedAt: int64(binary.BigEndian.Uint64(raw[8:16])),
	}
	copy(rec.ChallengeDigest[:], raw[16:48])
	return rec, nil
}

func decodeBinaryChallengeRecordV2(raw []byte) (record, error) {
	if len(raw) < challengeRecordV2FixedSize {
		return record{}, fmt.Errorf("%w: compact v2 record is %d bytes, need at least %d", errChallengeRecord, len(raw), challengeRecordV2FixedSize)
	}
	state, err := logicalRecordState(raw[challengeRecordStateOffset])
	if err != nil {
		return record{}, err
	}
	flags := raw[6]
	if flags&^byte(challengeRecordKnownFlags) != 0 || raw[7] != 1 || raw[10] != 0 || raw[11] != 0 {
		return record{}, fmt.Errorf("%w: unsupported v2 flags, algorithm or reserved bytes", errChallengeRecord)
	}
	hostLen64 := uint64(binary.BigEndian.Uint32(raw[72:76]))
	ipLen64 := uint64(binary.BigEndian.Uint32(raw[76:80]))
	uriLen64 := uint64(binary.BigEndian.Uint32(raw[80:84]))
	if hostLen64+ipLen64+uriLen64 != uint64(len(raw)-challengeRecordV2FixedSize) {
		return record{}, fmt.Errorf("%w: v2 field lengths do not match record size", errChallengeRecord)
	}
	offset := challengeRecordV2FixedSize
	hostLen, ipLen, uriLen := int(hostLen64), int(ipLen64), int(uriLen64)
	rec := record{
		State: state, Host: string(raw[offset : offset+hostLen]),
		Algorithm: AlgorithmArgon2ID, Iterations: uint32(raw[9]),
		MemoryKiB: binary.BigEndian.Uint32(raw[68:72]),
		NoJS:      flags&challengeRecordFlagNoJS != 0,
		IssuedAt:  int64(binary.BigEndian.Uint64(raw[12:20])),
	}
	offset += hostLen
	rec.IP = string(raw[offset : offset+ipLen])
	offset += ipLen
	rec.URI = string(raw[offset : offset+uriLen])
	copy(rec.ChallengeDigest[:], raw[20:52])
	copy(rec.Salt[:], raw[52:68])
	if err := rec.proofSpec().validate(); err != nil {
		return record{}, fmt.Errorf("%w: %v", errChallengeRecord, err)
	}
	return rec, nil
}

func binaryRecordState(state string) (byte, error) {
	switch state {
	case recordStateIssued:
		return challengeRecordStateIssued, nil
	case recordStateSpent:
		return challengeRecordStateSpent, nil
	default:
		return 0, fmt.Errorf("%w: unknown state %q", errChallengeRecord, state)
	}
}

func logicalRecordState(state byte) (string, error) {
	switch state {
	case challengeRecordStateIssued:
		return recordStateIssued, nil
	case challengeRecordStateSpent:
		return recordStateSpent, nil
	default:
		return "", fmt.Errorf("%w: unknown state %d", errChallengeRecord, state)
	}
}

// appendChallengeText reconstructs the client-facing lowercase hex digest in
// caller-provided scratch.
func (r *record) appendChallengeText(dst []byte) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, hex.EncodedLen(len(r.ChallengeDigest)))...)
	hex.Encode(dst[start:], r.ChallengeDigest[:])
	return dst
}
