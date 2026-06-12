// Package nowhere implements the Nowhere v1 QUIC proxy protocol.
// Protocol reverse-engineered from the Anywhere iOS client source code.
package nowhere

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

const (
	// AuthFrameLen is the fixed length of an auth frame: 8 (magic) + 32 (nonce) + 32 (tag).
	AuthFrameLen = 72

	// MaxTargetLen is the maximum byte length of a proxy target address.
	MaxTargetLen = 512

	// maxInputLen is the maximum byte length of key/spec/alpn inputs.
	maxInputLen = 255

	// field lengths for HKDF derivation
	derivedALPNLen     = 12
	specIDLen          = 8
	authMagicLen       = 8
	authInfoLen        = 32
	specCommitmentLen  = 32

	// UDP datagram types
	UDPTypeRequest  uint8 = 1
	UDPTypeResponse uint8 = 2
	UDPTypeClose    uint8 = 3
)

// EffectiveSpec holds all protocol parameters derived from key + spec + alpn.
// These are computed once and reused for the lifetime of a client configuration.
type EffectiveSpec struct {
	// EffectiveALPN is the ALPN string to use in QUIC TLS negotiation.
	EffectiveALPN string
	// DerivedALPN is the HKDF-derived ALPN (regardless of whether an explicit one was provided).
	DerivedALPN string
	// EffectiveSpecID is a base64url identifier for this spec (informational).
	EffectiveSpecID string
	// AuthMagic is the 8-byte magic prefix of the auth frame.
	AuthMagic []byte
	// AuthInfo is the 32-byte HMAC context info used in the auth tag.
	AuthInfo []byte
	// SpecCommitment is the 32-byte spec commitment included in the auth message.
	SpecCommitment []byte
}

// BuildEffectiveSpec derives all protocol parameters from the connection configuration.
//
// Derivation (mirrors Anywhere iOS client exactly):
//
//	effectiveSpec = spec (if non-empty) else key
//	specSalt      = SHA256(effectiveSpec)
//	prk           = HMAC-SHA256(key=specSalt, data=effectiveSpec)   // HKDF-Extract
//	authMagic     = HKDF-Expand(prk, "auth magic",      8)
//	authInfo      = HKDF-Expand(prk, "auth hmac info", 32)
//	specCommitment= HKDF-Expand(prk, "spec commitment", 32)
//	derivedALPN   = base64url_nopad(HKDF-Expand(prk, "alpn",       12))
//	specID        = base64url_nopad(HKDF-Expand(prk, "spec id",     8))
//	effectiveALPN = alpn (if non-empty) else derivedALPN
func BuildEffectiveSpec(key, spec, alpn string) (*EffectiveSpec, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("nowhere: key is required")
	}
	if len(key) > maxInputLen {
		return nil, fmt.Errorf("nowhere: key exceeds %d bytes", maxInputLen)
	}

	var effectiveSpecBytes []byte
	if spec != "" {
		if len(spec) > maxInputLen {
			return nil, fmt.Errorf("nowhere: spec exceeds %d bytes", maxInputLen)
		}
		effectiveSpecBytes = []byte(spec)
	} else {
		effectiveSpecBytes = []byte(key)
	}

	// specSalt = SHA256(effectiveSpec)
	saltArr := sha256.Sum256(effectiveSpecBytes)
	specSalt := saltArr[:]

	// prk = HKDF-Extract(salt=specSalt, ikm=effectiveSpec)
	prk := hkdfExtract(specSalt, effectiveSpecBytes)

	derivedALPNBytes := hkdfExpand(prk, []byte("alpn"), derivedALPNLen)
	derivedALPN := base64URLNoPad(derivedALPNBytes)

	effectiveALPN := derivedALPN
	if alpn != "" {
		if len(alpn) > maxInputLen {
			return nil, fmt.Errorf("nowhere: alpn exceeds %d bytes", maxInputLen)
		}
		effectiveALPN = alpn
	}

	return &EffectiveSpec{
		EffectiveALPN:   effectiveALPN,
		DerivedALPN:     derivedALPN,
		EffectiveSpecID: base64URLNoPad(hkdfExpand(prk, []byte("spec id"), specIDLen)),
		AuthMagic:       hkdfExpand(prk, []byte("auth magic"), authMagicLen),
		AuthInfo:        hkdfExpand(prk, []byte("auth hmac info"), authInfoLen),
		SpecCommitment:  hkdfExpand(prk, []byte("spec commitment"), specCommitmentLen),
	}, nil
}

// MakeAuthFrame constructs the 72-byte authentication frame.
//
// Frame layout:
//
//	[authMagic(8)] + [nonce(32)] + [HMAC-SHA256 tag(32)]
//
// HMAC message = authInfo(32) + specCommitment(32) + nonce(32)
// HMAC key     = SHA256(key_string)
func MakeAuthFrame(key string, ps *EffectiveSpec) ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nowhere: generate nonce: %w", err)
	}

	// message = authInfo + specCommitment + nonce
	message := make([]byte, 0, authInfoLen+specCommitmentLen+32)
	message = append(message, ps.AuthInfo...)
	message = append(message, ps.SpecCommitment...)
	message = append(message, nonce...)

	// derived = SHA256(key)
	derivedArr := sha256.Sum256([]byte(key))

	mac := hmac.New(sha256.New, derivedArr[:])
	mac.Write(message)
	tag := mac.Sum(nil)

	frame := make([]byte, 0, AuthFrameLen)
	frame = append(frame, ps.AuthMagic...)  // 8 bytes
	frame = append(frame, nonce...)          // 32 bytes
	frame = append(frame, tag...)            // 32 bytes
	return frame, nil
}

// EncodeTCPRequest encodes a proxy target address as a 2-byte-length-prefixed UTF-8 string.
func EncodeTCPRequest(address string) ([]byte, error) {
	return encodeTarget(address)
}

// EncodeUDPDatagram encodes a UDP datagram for sending over QUIC DATAGRAM.
//
// Format: [type(1)] + [flowID(8,big-endian)] + [2-byte target len] + [target UTF-8] + [payload]
func EncodeUDPDatagram(typ uint8, flowID uint64, target string, payload []byte) ([]byte, error) {
	targetBytes, err := encodeTarget(target)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+8+len(targetBytes)+len(payload))
	out = append(out, typ)
	out = binary.BigEndian.AppendUint64(out, flowID)
	out = append(out, targetBytes...)
	out = append(out, payload...)
	return out, nil
}

// UDPMessage represents a decoded inbound QUIC datagram.
type UDPMessage struct {
	Type    uint8
	FlowID  uint64
	Target  string
	Payload []byte
}

// DecodeUDPDatagram decodes a raw QUIC datagram into a UDPMessage.
// Returns nil if the datagram is malformed or is not a response/close type.
func DecodeUDPDatagram(data []byte) *UDPMessage {
	if len(data) < 11 { // 1 + 8 + 2 minimum
		return nil
	}
	typ := data[0]
	if typ != UDPTypeResponse && typ != UDPTypeClose {
		return nil
	}
	flowID := binary.BigEndian.Uint64(data[1:9])
	target, next, ok := decodeTarget(data, 9)
	if !ok {
		return nil
	}
	payload := make([]byte, len(data)-next)
	copy(payload, data[next:])
	return &UDPMessage{
		Type:    typ,
		FlowID:  flowID,
		Target:  target,
		Payload: payload,
	}
}

// UDPHeaderSize returns the byte size of the datagram header for a given target.
func UDPHeaderSize(target string) int {
	return 1 + 8 + 2 + len([]byte(target))
}

// ── HKDF helpers ─────────────────────────────────────────────────────────────

// hkdfExtract implements HKDF-Extract: HMAC-SHA256(key=salt, data=ikm).
func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpand implements HKDF-Expand (RFC 5869) using HMAC-SHA256.
//
// T(0) = ""
// T(n) = HMAC-SHA256(prk, T(n-1) || info || n)
func hkdfExpand(prk, info []byte, length int) []byte {
	var output []byte
	previous := []byte{}
	counter := byte(1)
	for len(output) < length {
		msg := make([]byte, 0, len(previous)+len(info)+1)
		msg = append(msg, previous...)
		msg = append(msg, info...)
		msg = append(msg, counter)
		mac := hmac.New(sha256.New, prk)
		mac.Write(msg)
		previous = mac.Sum(nil)
		output = append(output, previous...)
		counter++
	}
	return output[:length]
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

func base64URLNoPad(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func encodeTarget(address string) ([]byte, error) {
	b := []byte(address)
	if len(b) == 0 || len(b) > MaxTargetLen {
		return nil, fmt.Errorf("nowhere: invalid target length %d", len(b))
	}
	out := make([]byte, 0, 2+len(b))
	out = append(out, byte(len(b)>>8), byte(len(b)&0xFF))
	out = append(out, b...)
	return out, nil
}

func decodeTarget(data []byte, offset int) (string, int, bool) {
	if offset+2 > len(data) {
		return "", 0, false
	}
	length := (int(data[offset]) << 8) | int(data[offset+1])
	if length == 0 || length > MaxTargetLen || offset+2+length > len(data) {
		return "", 0, false
	}
	return string(data[offset+2 : offset+2+length]), offset + 2 + length, true
}
