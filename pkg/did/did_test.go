package did

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

// base58Vectors cross-checks the in-house base58btc implementation against
// vectors computed with an independent implementation (and, for the longer
// ones, matching the classic Bitcoin base58 test vectors). The leading-zero
// cases are the important ones: leading zero bytes must map to leading '1'
// characters, not silently disappear into the big-integer conversion.
var base58Vectors = []struct {
	hex     string
	encoded string
}{
	{"61", "2g"},
	{"626262", "a3gV"},
	{"636363", "aPEr"},
	{"00", "1"},
	{"0000", "11"},
	{"000000ff", "1115Q"},
	{"00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"},
	{"73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"},
}

func TestBase58Vectors(t *testing.T) {
	for _, v := range base58Vectors {
		raw, err := hex.DecodeString(v.hex)
		if err != nil {
			t.Fatalf("bad test vector hex %q: %v", v.hex, err)
		}

		if got := base58Encode(raw); got != v.encoded {
			t.Errorf("base58Encode(%s) = %q, want %q", v.hex, got, v.encoded)
		}

		decoded, err := base58Decode(v.encoded)
		if err != nil {
			t.Errorf("base58Decode(%q) error: %v", v.encoded, err)
		} else if !bytes.Equal(decoded, raw) {
			t.Errorf("base58Decode(%q) = %x, want %s", v.encoded, decoded, v.hex)
		}
	}
}

func TestBase58DecodeRejectsInvalidCharacters(t *testing.T) {
	// '0', 'O', 'I', and 'l' are excluded from the base58 alphabet.
	for _, s := range []string{"0", "O", "I", "l", "2g!"} {
		if _, err := base58Decode(s); err == nil {
			t.Errorf("base58Decode(%q) succeeded, want error", s)
		}
	}
}

// didKeyVectors pins the full did:key encoding against an independent
// implementation. The vectors deliberately include public keys whose first
// byte is 0x00 and one with several leading zero bytes: the multicodec
// prefix precedes them in the encoded payload, so these exercise interior
// zeros in the base58 conversion — a silent-corruption hotspot.
var didKeyVectors = []struct {
	pubHex string
	did    string
}{
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP",
	},
	{
		"003b6a27bcceb6a42d62a3a8d02a6f0d736343215771de243a63ac048a18b59d",
		"did:key:z6MkeUAbJ8Aa9WjtnuacNs9nFyzSM4uH8GWWcxyhxoxr1cZ2",
	},
	{
		"000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"did:key:z6MkeTG3izctgd7LfFVX9MitaWzcFUtw9MjEn62JZUKfQJwK",
	},
	{
		"3b6a27bcceb6a42d62a3a8d02a6f0d73f5e214a5f5e214a5f5e214a5f5e214a5",
		"did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99mXQkL3vUbEr8W3hosJqFr",
	},
}

func TestDIDKeyVectors(t *testing.T) {
	for _, v := range didKeyVectors {
		pub, err := hex.DecodeString(v.pubHex)
		if err != nil {
			t.Fatalf("bad test vector hex %q: %v", v.pubHex, err)
		}

		got, err := FromPublicKey(ed25519.PublicKey(pub))
		if err != nil {
			t.Fatalf("FromPublicKey(%s) error: %v", v.pubHex, err)
		}
		if got != v.did {
			t.Errorf("FromPublicKey(%s) = %q, want %q", v.pubHex, got, v.did)
		}

		recovered, err := PublicKey(v.did)
		if err != nil {
			t.Fatalf("PublicKey(%q) error: %v", v.did, err)
		}
		if !bytes.Equal(recovered, pub) {
			t.Errorf("PublicKey(%q) = %x, want %s", v.did, recovered, v.pubHex)
		}
	}
}

func TestRoundTripRandomKeys(t *testing.T) {
	for i := 0; i < 256; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey error: %v", err)
		}
		// Force the leading-zero edge case on a portion of the keys.
		if i%4 == 0 {
			pub[0] = 0
		}
		if i%8 == 0 {
			pub[1] = 0
		}

		d, err := FromPublicKey(pub)
		if err != nil {
			t.Fatalf("FromPublicKey error: %v", err)
		}
		if !strings.HasPrefix(d, Prefix) {
			t.Fatalf("DID %q does not start with %q", d, Prefix)
		}

		recovered, err := PublicKey(d)
		if err != nil {
			t.Fatalf("PublicKey(%q) error: %v", d, err)
		}
		if !bytes.Equal(recovered, pub) {
			t.Fatalf("round trip mismatch: key %x → %q → %x", pub, d, recovered)
		}
	}
}

func TestPublicKeyRejectsMalformedDIDs(t *testing.T) {
	bad := []string{
		"",
		"did:web:example.com",                  // wrong method
		"did:key:uABCD",                        // wrong multibase (not base58btc)
		"did:key:z0",                           // invalid base58 character
		"did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99m", // truncated key
		"did:key:z2g",                          // wrong multicodec prefix
	}
	for _, d := range bad {
		if _, err := PublicKey(d); err == nil {
			t.Errorf("PublicKey(%q) succeeded, want error", d)
		}
		if err := Validate(d); err == nil {
			t.Errorf("Validate(%q) succeeded, want error", d)
		}
	}
}

func TestFromPublicKeyRejectsWrongLength(t *testing.T) {
	if _, err := FromPublicKey(make([]byte, 16)); err == nil {
		t.Error("FromPublicKey(16 bytes) succeeded, want error")
	}
}
