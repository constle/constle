// Package did implements the did:key DID method for Ed25519 public keys.
//
// A did:key identifier is self-describing: the identifier itself encodes the
// public key, so any party can recover the key directly from the DID string
// with no resolution service. The format is:
//
//	did:key:z<base58btc(varint(0xed) || 32-byte-public-key)>
//
// where 0xed is the multicodec code for ed25519-pub (varint-encoded as the
// two bytes 0xed 0x01) and "z" is the multibase prefix for base58btc.
// See https://w3c-ccg.github.io/did-method-key/ for the method spec.
//
// The encoding is implemented in-house to keep the open core dependency-free;
// it is validated against the classic base58 test vectors, including the
// leading-zero-byte edge cases.
package did

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"strings"
)

// Prefix is the scheme-and-method prefix of every identifier this package
// produces, including the base58btc multibase marker.
const Prefix = "did:key:z"

// encodedLen is the base58btc digit count of every payload this package
// encodes. The payload is fixed-size: the 2-byte ed25519-pub multicodec
// followed by a 32-byte key, 34 bytes in all. Its integer value N always
// lies in [0xed01 * 2^256, 0xed02 * 2^256), and 58^46 < N < 58^47 across
// that whole range, so the base58 form is exactly 47 digits; and because the
// first payload byte is 0xed, never zero, no leading '1' digits ever appear.
// TestEncodedLenIsExact pins both extremes against the encoder.
const encodedLen = 47

// MaxLen is the longest identifier PublicKey accepts. Every did:key Ed25519
// identifier is exactly this long (Prefix plus encodedLen digits), so it is
// also the only valid length; PublicKey rejects longer input on byte count
// alone, before decoding anything, so callers that receive DIDs from
// untrusted peers get a bounded cost without a check of their own.
const MaxLen = len(Prefix) + encodedLen

// ed25519PubMulticodec is the varint encoding of the multicodec code 0xed
// (ed25519-pub), prepended to the raw public key before base58 encoding.
var ed25519PubMulticodec = []byte{0xed, 0x01}

// FromPublicKey derives the did:key identifier for an Ed25519 public key.
func FromPublicKey(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid Ed25519 public key length %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	payload := make([]byte, 0, len(ed25519PubMulticodec)+ed25519.PublicKeySize)
	payload = append(payload, ed25519PubMulticodec...)
	payload = append(payload, pub...)
	return Prefix + base58Encode(payload), nil
}

// PublicKey recovers the Ed25519 public key encoded in a did:key identifier.
// It fails on any other DID method, multibase encoding, or key type — did:key
// with Ed25519 is the only identity format constle supports.
func PublicKey(did string) (ed25519.PublicKey, error) {
	// Length before anything else: before the prefix check, whose error
	// quotes the input, and before base58Decode, whose cost is quadratic in
	// the input length. This string arrives from unauthenticated peers (an
	// A2A envelope's "from" is decoded here BEFORE its signature can be
	// checked, because the verification key comes from the DID itself), so
	// an oversized value must fail on byte count alone: no work proportional
	// to its content, and no echo of it into an error, audit entry, or
	// response. The error therefore reports the length, never the value.
	if len(did) > MaxLen {
		return nil, fmt.Errorf("invalid DID: %d bytes, longer than any did:key Ed25519 identifier (%d bytes)", len(did), MaxLen)
	}

	if !strings.HasPrefix(did, Prefix) {
		return nil, fmt.Errorf("invalid DID %q: must start with %q (did:key with base58btc encoding)", did, Prefix)
	}

	payload, err := base58Decode(strings.TrimPrefix(did, Prefix))
	if err != nil {
		return nil, fmt.Errorf("invalid DID %q: %w", did, err)
	}

	if len(payload) < len(ed25519PubMulticodec) ||
		payload[0] != ed25519PubMulticodec[0] || payload[1] != ed25519PubMulticodec[1] {
		return nil, fmt.Errorf("invalid DID %q: not an ed25519-pub key (unexpected multicodec prefix)", did)
	}

	key := payload[len(ed25519PubMulticodec):]
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid DID %q: embedded key is %d bytes, want %d", did, len(key), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(key), nil
}

// Validate reports whether the string is a well-formed did:key identifier for
// an Ed25519 public key.
func Validate(did string) error {
	_, err := PublicKey(did)
	return err
}

// base58Alphabet is the base58btc (Bitcoin) alphabet used by multibase "z".
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode encodes bytes as base58btc. Each leading zero byte is encoded
// as a leading '1' — the classic base58 edge case, covered by test vectors.
func base58Encode(input []byte) string {
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	num := new(big.Int).SetBytes(input)
	radix := big.NewInt(58)
	mod := new(big.Int)

	var digits []byte
	for num.Sign() > 0 {
		num.DivMod(num, radix, mod)
		digits = append(digits, base58Alphabet[mod.Int64()])
	}

	var b strings.Builder
	b.Grow(zeros + len(digits))
	for i := 0; i < zeros; i++ {
		b.WriteByte('1')
	}
	for i := len(digits) - 1; i >= 0; i-- {
		b.WriteByte(digits[i])
	}
	return b.String()
}

// base58Decode decodes a base58btc string. Each leading '1' decodes to a
// leading zero byte, mirroring base58Encode.
//
// The input is bounded to encodedLen bytes before any arithmetic: the loop
// is quadratic in len(s), since num gains ~5.9 bits per digit and every
// Mul/Add walks all of it (tens of seconds of CPU for 1 MiB of digits on a
// current core, 16x more per 4x of input, over an hour at the 10 MB A2A body
// cap). PublicKey rejects oversized identifiers first with a friendlier
// message; this guard keeps the decoder safe on its own, so no future caller
// can reach the loop with unbounded input.
func base58Decode(s string) ([]byte, error) {
	if len(s) > encodedLen {
		return nil, fmt.Errorf("base58 input is %d bytes, longer than the %d-byte maximum", len(s), encodedLen)
	}

	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}

	num := big.NewInt(0)
	radix := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(base58Alphabet, s[i])
		if v < 0 {
			return nil, fmt.Errorf("invalid base58 character %q at position %d", s[i], i)
		}
		num.Mul(num, radix)
		num.Add(num, big.NewInt(int64(v)))
	}

	decoded := num.Bytes()
	out := make([]byte, zeros+len(decoded))
	copy(out[zeros:], decoded)
	return out, nil
}
