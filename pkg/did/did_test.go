package did

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

// oversizedDeadline bounds how long the oversized-input regression test
// waits for a verdict. It is a sanity bound, not a performance assertion:
// the fixed code answers in microseconds, while the unbounded decoder it
// guards against needs over an hour for the 10 MiB case, so the value only
// has to be generous enough for a slow, loaded CI runner.
const oversizedDeadline = 30 * time.Second

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
		if len(d) != MaxLen {
			t.Fatalf("DID %q is %d bytes, want exactly MaxLen (%d)", d, len(d), MaxLen)
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

// TestEncodedLenIsExact pins encodedLen (and so MaxLen) against the encoder
// at both extremes of the payload space: the all-zero key gives the smallest
// integer any ed25519-pub payload can encode, the all-0xff key the largest.
// Both must land on exactly encodedLen digits with no leading '1', which is
// what lets PublicKey reject on length alone without turning away any
// valid identifier. The published vectors are checked the same way.
func TestEncodedLenIsExact(t *testing.T) {
	for name, key := range map[string][]byte{
		"all-zero key": make([]byte, ed25519.PublicKeySize),
		"all-0xff key": bytes.Repeat([]byte{0xff}, ed25519.PublicKeySize),
	} {
		payload := append(append([]byte{}, ed25519PubMulticodec...), key...)
		enc := base58Encode(payload)
		if len(enc) != encodedLen {
			t.Errorf("%s: encodes to %d base58 digits, want encodedLen = %d", name, len(enc), encodedLen)
		}
		if enc[0] == '1' {
			t.Errorf("%s: encoding %q starts with '1' — a leading zero byte is impossible after the 0xed multicodec", name, enc)
		}
		d, err := FromPublicKey(ed25519.PublicKey(key))
		if err != nil {
			t.Fatalf("%s: FromPublicKey: %v", name, err)
		}
		if len(d) != MaxLen {
			t.Errorf("%s: DID is %d bytes, want MaxLen = %d", name, len(d), MaxLen)
		}
	}
	for _, v := range didKeyVectors {
		if len(v.did) != MaxLen {
			t.Errorf("vector %q is %d bytes, want MaxLen = %d", v.did, len(v.did), MaxLen)
		}
	}
}

// TestPublicKeyRejectsOversizedDIDBeforeDecoding is the regression test for
// the unbounded-decode CPU exhaustion: base58Decode's cost is quadratic in
// the input length, and an A2A peer controls the "from" DID that reaches it
// before any signature check. Before the length bound, decoding a 10 MiB
// string (the A2A body cap) pinned a core for on the order of an hour
// before the value was finally rejected; now it must be rejected on byte
// count alone, immediately, and the error must describe the length without
// echoing the input.
func TestPublicKeyRejectsOversizedDIDBeforeDecoding(t *testing.T) {
	// Every byte after the prefix is a valid base58 digit, so nothing but
	// the length bound can stop the decoder from doing the full quadratic
	// walk.
	cases := map[string]string{
		"one byte over": Prefix + strings.Repeat("z", encodedLen+1),
		"10 MiB":        Prefix + strings.Repeat("z", 10<<20),
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			type result struct {
				err   error
				taken time.Duration
			}
			done := make(chan result, 1)
			go func() {
				start := time.Now()
				_, err := PublicKey(d)
				done <- result{err, time.Since(start)}
			}()

			var res result
			select {
			case res = <-done:
			case <-time.After(oversizedDeadline):
				// The old decoder is still spinning at this point (and will
				// for a long while) — the bound is not being applied before
				// the decode.
				t.Fatalf("PublicKey on a %d-byte DID did not return within %s — input length is not bounded before decoding", len(d), oversizedDeadline)
			}

			if res.err == nil {
				t.Fatalf("PublicKey accepted a %d-byte DID", len(d))
			}
			msg := res.err.Error()
			if len(msg) > 256 {
				t.Fatalf("error is %d bytes — it echoes the oversized input: %.80s...", len(msg), msg)
			}
			if !strings.Contains(msg, strconv.Itoa(len(d))+" bytes") || !strings.Contains(msg, strconv.Itoa(MaxLen)) {
				t.Fatalf("error %q does not report the input length and the %d-byte bound", msg, MaxLen)
			}
			if err := Validate(d); err == nil {
				t.Fatalf("Validate accepted a %d-byte DID", len(d))
			}
			t.Logf("rejected %d bytes in %s: %v", len(d), res.taken, res.err)
		})
	}
}

// TestBase58DecodeBoundsInputLength checks the decoder's own guard, which
// holds even for a caller that skips PublicKey: exactly encodedLen digits
// decode, one more is refused before any arithmetic.
func TestBase58DecodeBoundsInputLength(t *testing.T) {
	if _, err := base58Decode(strings.Repeat("z", encodedLen)); err != nil {
		t.Errorf("base58Decode(%d digits) error: %v", encodedLen, err)
	}
	for _, n := range []int{encodedLen + 1, 1 << 16} {
		_, err := base58Decode(strings.Repeat("z", n))
		if err == nil {
			t.Errorf("base58Decode(%d digits) succeeded, want length error", n)
			continue
		}
		if len(err.Error()) > 256 || !strings.Contains(err.Error(), "bytes") {
			t.Errorf("base58Decode(%d digits) error %.80q does not report the length bound", n, err.Error())
		}
	}
}
