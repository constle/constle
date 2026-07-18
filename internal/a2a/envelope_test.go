package a2a

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/constle/constle/pkg/did"
)

// testSigner is an in-memory Signer for tests, derived from a seed byte.
type testSigner struct {
	didStr string
	priv   ed25519.PrivateKey
}

func newTestSigner(t *testing.T, seed byte) *testSigner {
	t.Helper()
	seedBytes := make([]byte, ed25519.SeedSize)
	seedBytes[0] = seed
	priv := ed25519.NewKeyFromSeed(seedBytes)
	didStr, err := did.FromPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("cannot derive test DID: %v", err)
	}
	return &testSigner{didStr: didStr, priv: priv}
}

func (s *testSigner) DID() string            { return s.didStr }
func (s *testSigner) Sign(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }

func TestSealOpenRoundTrip(t *testing.T) {
	alice := newTestSigner(t, 1)
	bob := newTestSigner(t, 2)

	wire, sealed, err := Seal(alice, bob.DID(), "", []byte(`{"task":"ping"}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	env, err := Open(wire)
	if err != nil {
		t.Fatalf("Open on a freshly sealed envelope: %v", err)
	}
	if env.From != alice.DID() || env.To != bob.DID() {
		t.Errorf("from/to = %s/%s, want %s/%s", env.From, env.To, alice.DID(), bob.DID())
	}
	if env.MsgID != sealed.MsgID {
		t.Errorf("msg_id changed in transit: %s != %s", env.MsgID, sealed.MsgID)
	}
	if string(env.Body) != `{"task":"ping"}` {
		t.Errorf("body = %s", env.Body)
	}

	// A trailing newline (common with HTTP bodies) must not break framing.
	if _, err := Open(append(bytes.Clone(wire), '\n')); err != nil {
		t.Errorf("Open with trailing newline: %v", err)
	}
}

func TestSealRejectsNonJSONBody(t *testing.T) {
	alice := newTestSigner(t, 1)
	if _, _, err := Seal(alice, newTestSigner(t, 2).DID(), "", []byte("not json")); err == nil {
		t.Fatal("Seal accepted a non-JSON body")
	}
}

func TestOpenRejectsTamperedBody(t *testing.T) {
	alice := newTestSigner(t, 1)
	wire, _, err := Seal(alice, newTestSigner(t, 2).DID(), "", []byte(`{"amount":10}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tampered := bytes.Replace(wire, []byte(`"amount":10`), []byte(`"amount":99`), 1)
	if bytes.Equal(tampered, wire) {
		t.Fatal("test bug: tampering did not change the wire bytes")
	}

	_, err = Open(tampered)
	assertReject(t, err, ReasonBadSignature)
}

func TestOpenRejectsForgedSignature(t *testing.T) {
	alice := newTestSigner(t, 1)
	mallory := newTestSigner(t, 3)
	bobDID := newTestSigner(t, 2).DID()

	// Mallory signs a message but claims it is from Alice: sign with
	// mallory's key, then swap the from field to alice's DID.
	wire, _, err := Seal(mallory, bobDID, "", []byte(`{"task":"pay"}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	forged := bytes.Replace(wire, []byte(mallory.DID()), []byte(alice.DID()), 1)

	_, err = Open(forged)
	assertReject(t, err, ReasonBadSignature)
}

func TestOpenRejectsResignedEnvelope(t *testing.T) {
	// Mallory intercepts Alice's envelope, alters it, and re-signs with her
	// own key while keeping from=alice. The self-describing DID makes this
	// fail: the key recovered from `from` is Alice's, not Mallory's.
	alice := newTestSigner(t, 1)
	mallory := newTestSigner(t, 3)
	bobDID := newTestSigner(t, 2).DID()

	wire, env, err := Seal(alice, bobDID, "", []byte(`{"amount":10}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	unsigned := bytes.TrimSuffix(wire, []byte(`,"sig":"`+env.Sig+`"}`))
	unsigned = append(bytes.Clone(unsigned), '}')
	resigned := base64.StdEncoding.EncodeToString(mallory.Sign(unsigned))
	rewired := bytes.Replace(wire, []byte(env.Sig), []byte(resigned), 1)

	_, err = Open(rewired)
	assertReject(t, err, ReasonBadSignature)
}

func TestOpenRejectsMalformed(t *testing.T) {
	for name, wire := range map[string][]byte{
		"garbage":    []byte("%%%%"),
		"empty":      {},
		"json array": []byte(`[]`),
		"no sig":     []byte(`{"from":"did:key:zabc","to":"did:key:zdef","msg_id":"1"}`),
		"bad did":    []byte(`{"from":"did:web:x","to":"y","msg_id":"1","timestamp":"2026-07-18T00:00:00Z","sig":"aaaa"}`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Open(wire)
			assertReject(t, err, ReasonMalformed)
		})
	}
}

func TestReplayGuard(t *testing.T) {
	alice := newTestSigner(t, 1)
	bobDID := newTestSigner(t, 2).DID()
	guard := newReplayGuard()

	wire, _, err := Seal(alice, bobDID, "", []byte(`{"n":1}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env, err := Open(wire)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := guard.check(env); err != nil {
		t.Fatalf("first delivery rejected: %v", err)
	}

	// The exact same validly signed envelope again: replay.
	replayed, err := Open(wire)
	if err != nil {
		t.Fatalf("Open (replay): %v", err)
	}
	assertReject(t, guard.check(replayed), ReasonReplay)

	// A fresh envelope still passes.
	wire2, _, err := Seal(alice, bobDID, "", []byte(`{"n":2}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env2, _ := Open(wire2)
	if err := guard.check(env2); err != nil {
		t.Fatalf("fresh envelope rejected after a replay: %v", err)
	}
}

func TestReplayGuardRejectsStaleTimestamp(t *testing.T) {
	guard := newReplayGuard()
	env := &Envelope{MsgID: "stale", Timestamp: time.Now().UTC().Add(-replayWindow - time.Minute)}
	assertReject(t, guard.check(env), ReasonStaleTimestamp)

	future := &Envelope{MsgID: "future", Timestamp: time.Now().UTC().Add(replayWindow + time.Minute)}
	assertReject(t, guard.check(future), ReasonStaleTimestamp)
}

// assertReject fails the test unless err is a *RejectError with the reason.
func assertReject(t *testing.T, err error, want RejectReason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected rejection %q, got nil", want)
	}
	re, ok := err.(*RejectError)
	if !ok {
		t.Fatalf("expected *RejectError, got %T: %v", err, err)
	}
	if re.Reason != want {
		t.Fatalf("reason = %q (%s), want %q", re.Reason, re.Detail, want)
	}
	if !strings.Contains(re.Error(), string(want)) {
		t.Fatalf("error text %q does not name the reason", re.Error())
	}
}
