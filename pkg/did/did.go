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
func base58Decode(s string) ([]byte, error) {
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
