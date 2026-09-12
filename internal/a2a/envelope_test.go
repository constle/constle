package a2a

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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

// oversizedDeadline bounds how long the oversized-DID regression tests wait
// for a verdict. It is a sanity bound, not a performance assertion: the
// fixed code answers in well under a second even under -race, while the
// unbounded decoder these tests guard against needs over an hour for a
// body-cap-sized DID, so the value only has to be generous enough for a
// slow, loaded CI runner.
const oversizedDeadline = 30 * time.Second

// oversizedFromEnvelope builds the largest envelope that fits under the
// public listener's body cap, with every byte after the prefix of its "from"
// a valid base58 digit: nothing but a length bound can stop the DID decoder
// from walking all of it. The envelope is otherwise well-framed, so the
// sender DID is the first thing Open examines.
func oversizedFromEnvelope(t *testing.T, to string) []byte {
	t.Helper()
	wire, err := json.Marshal(Envelope{
		From:      did.Prefix + strings.Repeat("z", maxBodyBytes-1024),
		To:        to,
		MsgID:     "1",
		Timestamp: time.Now().UTC(),
		Sig:       "aaaa",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(wire) > maxBodyBytes {
		t.Fatalf("test bug: wire is %d bytes, over the %d-byte cap", len(wire), maxBodyBytes)
	}
	return wire
}

// TestOpenRejectsOversizedSenderDIDBeforeVerifying is the a2a-side
// regression test for the unbounded DID decode: Open recovers the
// verification key from "from" BEFORE it can check any signature, and the
// base58 decoder behind it was quadratic in the string length. A peer that
// sent a body-cap-sized "from" used to pin a host core for on the order of
// an hour per request, unauthenticated. It must now be refused on length,
// immediately, without the value being echoed into the rejection detail
// (which is written to the audit log).
func TestOpenRejectsOversizedSenderDIDBeforeVerifying(t *testing.T) {
	wire := oversizedFromEnvelope(t, newTestSigner(t, 2).DID())

	done := make(chan error, 1)
	go func() {
		_, err := Open(wire)
		done <- err
	}()
	var err error
	select {
	case err = <-done:
	case <-time.After(oversizedDeadline):
		t.Fatalf("Open did not reject a %d-byte envelope within %s — the sender DID is decoded without a length bound", len(wire), oversizedDeadline)
	}

	assertReject(t, err, ReasonMalformed)
	re, ok := err.(*RejectError)
	if !ok {
		t.Fatalf("expected *RejectError, got %T", err)
	}
	if len(re.Detail) > 256 {
		t.Fatalf("rejection detail is %d bytes — it echoes the oversized DID: %.80s...", len(re.Detail), re.Detail)
	}
	if !strings.Contains(re.Detail, "sender DID") {
		t.Fatalf("rejection detail %q does not attribute the failure to the sender DID", re.Detail)
	}
}

func TestReplayGuard(t *testing.T) {
	alice := newTestSigner(t, 1)
	bobDID := newTestSigner(t, 2).DID()
	guard := newReplayGuard(nil)

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
	guard := newReplayGuard(nil)
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
