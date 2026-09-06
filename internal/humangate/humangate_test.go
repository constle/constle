package humangate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/constle/constle/pkg/did"
)

// testApprover is a real Ed25519 keypair standing in for the human-gates
// approver, plus the did:key string an Agentfile would declare for it.
type testApprover struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	did  string
}

func newTestApprover(t *testing.T) testApprover {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error: %v", err)
	}
	didStr, err := did.FromPublicKey(pub)
	if err != nil {
		t.Fatalf("did.FromPublicKey() error: %v", err)
	}
	return testApprover{pub: pub, priv: priv, did: didStr}
}

// sign produces a genuinely valid DecisionResponse: the signature is a real
// Ed25519 signature over the exact payload spec §6 defines.
func (a testApprover) sign(requestID, decision, subjectDigest string) DecisionResponse {
	payload := signedPayload(requestID, decision, subjectDigest)
	sig := ed25519.Sign(a.priv, payload)
	return DecisionResponse{
		RequestID:     requestID,
		Decision:      decision,
		SubjectDigest: subjectDigest,
		Signature:     base64.StdEncoding.EncodeToString(sig),
		DecidedAt:     time.Now().UTC(),
	}
}

func TestVerifyDecisionValidSignatureApproved(t *testing.T) {
	approver := newTestApprover(t)
	digest := "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"
	resp := approver.sign("hg_7f3a9c2e", "approved", digest)

	approved, reason, err := VerifyDecision(approver.did, "hg_7f3a9c2e", digest, resp)
	if err != nil {
		t.Fatalf("VerifyDecision() error: %v", err)
	}
	if !approved {
		t.Errorf("approved = false, want true")
	}
	if reason != ReasonApproved {
		t.Errorf("reason = %q, want %q", reason, ReasonApproved)
	}
}

func TestVerifyDecisionInvalidSignatureRejected(t *testing.T) {
	approver := newTestApprover(t)
	other := newTestApprover(t)
	digest := "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"

	// Signed with a DIFFERENT key than the one named by approver_pubkey —
	// simulates a forged or misattributed decision.
	resp := other.sign("hg_7f3a9c2e", "approved", digest)

	approved, reason, err := VerifyDecision(approver.did, "hg_7f3a9c2e", digest, resp)
	if approved {
		t.Fatal("approved = true for a signature from the wrong key, want false")
	}
	if reason != ReasonSignatureInvalid {
		t.Errorf("reason = %q, want %q", reason, ReasonSignatureInvalid)
	}
	if err == nil {
		t.Error("err = nil, want a descriptive error")
	}
}

func TestVerifyDecisionTamperedPayloadRejected(t *testing.T) {
	approver := newTestApprover(t)
	digest := "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"

	// Sign one decision, then swap in "approved" after the fact — the
	// signature no longer covers the bytes actually being evaluated.
	resp := approver.sign("hg_7f3a9c2e", "denied", digest)
	resp.Decision = "approved"

	approved, reason, err := VerifyDecision(approver.did, "hg_7f3a9c2e", digest, resp)
	if approved {
		t.Fatal("approved = true for a decision tampered with after signing, want false")
	}
	if reason != ReasonSignatureInvalid {
		t.Errorf("reason = %q, want %q", reason, ReasonSignatureInvalid)
	}
	if err == nil {
		t.Error("err = nil, want a descriptive error")
	}
}

func TestVerifyDecisionMalformedSignatureRejected(t *testing.T) {
	approver := newTestApprover(t)
	digest := "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"
	resp := approver.sign("hg_7f3a9c2e", "approved", digest)
	resp.Signature = "not-valid-base64!!!"

	approved, reason, err := VerifyDecision(approver.did, "hg_7f3a9c2e", digest, resp)
	if approved {
		t.Fatal("approved = true with an undecodable signature, want false")
	}
	if reason != ReasonSignatureInvalid {
		t.Errorf("reason = %q, want %q", reason, ReasonSignatureInvalid)
	}
	if err == nil {
		t.Error("err = nil, want a descriptive error")
	}
}

func TestVerifyDecisionDigestMismatchRejected(t *testing.T) {
	approver := newTestApprover(t)
	sentDigest := "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"
	staleDigest := "sha256:00000000000000000000000000000000000000000000000000000000000000"

	// The approver genuinely signed staleDigest — the signature is valid —
	// but it is not the digest of the tool call Constle actually sent.
	resp := approver.sign("hg_7f3a9c2e", "approved", staleDigest)

	approved, reason, err := VerifyDecision(approver.did, "hg_7f3a9c2e", sentDigest, resp)
	if approved {
		t.Fatal("approved = true for a genuinely signed but mismatched digest, want false")
	}
	if reason != ReasonDigestMismatch {
		t.Errorf("reason = %q, want %q", reason, ReasonDigestMismatch)
	}
	if err == nil {
		t.Error("err = nil, want a descriptive error")
	}
}

// TestVerifyDecisionReplayedAcrossRequestsWithSameDigestRejected is the
// regression test for the gap this check closes (HG01).
//
// Two gates for the *same* tool call — same name, same arguments — share a
// subject_digest by construction: SubjectDigest is a pure function of those
// two inputs, so nothing about being a second, later, separately-approved
// invocation changes the digest. What separates them is request_id, and only
// request_id.
//
// So a decision the approver genuinely signed for gate A is, byte for byte, a
// valid Ed25519 signature carrying a subject_digest that matches gate B's
// exactly. Signature verification passes. The digest check passes. If nothing
// compares request_id against the id B actually sent, one human "yes" to a
// repeatable call is replayable into every later occurrence of that call —
// the second, tenth, hundredth identical transfer approves itself off the
// first decision.
func TestVerifyDecisionReplayedAcrossRequestsWithSameDigestRejected(t *testing.T) {
	approver := newTestApprover(t)

	// One tool call, digested once — both gates below are for exactly this
	// call, which is precisely why they cannot be told apart by digest.
	digest, err := SubjectDigest("transfer_funds", json.RawMessage(`{"to":"acct_9f3","amount_cents":125000}`))
	if err != nil {
		t.Fatalf("SubjectDigest() error: %v", err)
	}

	const (
		requestA = "hg_aaaa1111" // the gate the human actually approved
		requestB = "hg_bbbb2222" // a later, identical call awaiting its own decision
	)

	// A real approval, genuinely signed by the real approver key, for A.
	decisionForA := approver.sign(requestA, "approved", digest)

	// Baseline: this decision is entirely valid *for the gate it was signed
	// for*. If this fails, the case below proves nothing.
	approved, reason, err := VerifyDecision(approver.did, requestA, digest, decisionForA)
	if err != nil {
		t.Fatalf("VerifyDecision() for its own request error: %v", err)
	}
	if !approved || reason != ReasonApproved {
		t.Fatalf("decision for request A did not verify for request A: approved = %v, reason = %q", approved, reason)
	}

	// The gap: replay A's decision at gate B. Same digest, different gate.
	approved, reason, err = VerifyDecision(approver.did, requestB, digest, decisionForA)
	if approved {
		t.Fatal("approved = true for a decision signed for a different request_id, want false — " +
			"one approval of a repeatable tool call must not answer every later identical gate")
	}
	if reason != ReasonRequestIDMismatch {
		t.Errorf("reason = %q, want %q — a request_id mismatch is its own failure, not a digest or signature failure",
			reason, ReasonRequestIDMismatch)
	}
	if err == nil {
		t.Error("err = nil, want a descriptive error naming both request ids")
	}

	// The digest genuinely matches; nothing here is caught by the digest
	// check, and the signature is genuinely the approver's. Assert that
	// explicitly so a future refactor cannot "fix" this test by making the
	// digests differ.
	if decisionForA.SubjectDigest != digest {
		t.Errorf("test fixture is wrong: the replayed decision's digest %q should match gate B's %q exactly",
			decisionForA.SubjectDigest, digest)
	}
}

// TestVerifyDecisionRequestIDMismatchNotRescuedBySignature pins the reason
// the explicit comparison exists: request_id is inside the signed payload, so
// a decision for the wrong gate is not a forgery — it verifies cryptographically
// and must still be rejected on the binding alone.
func TestVerifyDecisionRequestIDMismatchNotRescuedBySignature(t *testing.T) {
	approver := newTestApprover(t)
	digest := "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"
	resp := approver.sign("hg_signed_for_this", "approved", digest)

	// Confirm the signature really does verify over the response's own bytes,
	// so the rejection below cannot be attributed to a bad signature.
	if !ed25519.Verify(approver.pub, signedPayload(resp.RequestID, resp.Decision, resp.SubjectDigest),
		mustDecodeB64(t, resp.Signature)) {
		t.Fatal("test fixture is wrong: the signature should verify over the response's own fields")
	}

	approved, reason, _ := VerifyDecision(approver.did, "hg_waiting_on_this", digest, resp)
	if approved {
		t.Fatal("approved = true, want false")
	}
	if reason == ReasonSignatureInvalid {
		t.Error("reason = signature_invalid, but the signature is genuinely valid — " +
			"signature coverage alone cannot catch a wrong-gate decision")
	}
	if reason != ReasonRequestIDMismatch {
		t.Errorf("reason = %q, want %q", reason, ReasonRequestIDMismatch)
	}
}

func mustDecodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return b
}

func TestVerifyDecisionMalformedOrMissingDecisionRejected(t *testing.T) {
	approver := newTestApprover(t)
	digest := "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"

	for _, decision := range []string{"denied", "", "Approved", "approved ", "maybe"} {
		resp := approver.sign("hg_7f3a9c2e", decision, digest)

		approved, reason, err := VerifyDecision(approver.did, "hg_7f3a9c2e", digest, resp)
		if approved {
			t.Errorf("decision %q: approved = true, want false", decision)
		}
		if reason != ReasonNotApproved {
			t.Errorf("decision %q: reason = %q, want %q", decision, reason, ReasonNotApproved)
		}
		if err != nil {
			t.Errorf("decision %q: err = %v, want nil (a validly-signed denial is not an error)", decision, err)
		}
	}
}

func TestVerifyDecisionInvalidApproverPubkeyRejected(t *testing.T) {
	digest := "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"
	resp := DecisionResponse{
		RequestID:     "hg_7f3a9c2e",
		Decision:      "approved",
		SubjectDigest: digest,
		Signature:     base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}

	for _, badKey := range []string{
		"",
		"not-a-did-at-all",
		"did:key:z6Mk" + "not-base58!!!",
		"did:web:example.com",
	} {
		approved, reason, err := VerifyDecision(badKey, "hg_7f3a9c2e", digest, resp)
		if approved {
			t.Errorf("approverPubkey %q: approved = true, want false", badKey)
		}
		if reason != ReasonSignatureInvalid {
			t.Errorf("approverPubkey %q: reason = %q, want %q", badKey, reason, ReasonSignatureInvalid)
		}
		if err == nil {
			t.Errorf("approverPubkey %q: err = nil, want error", badKey)
		}
	}
}

func TestSubjectDigestIsCanonicalAndDeterministic(t *testing.T) {
	// Two byte-different-but-semantically-identical argument encodings
	// (reordered keys, extra whitespace) must digest identically — that is
	// the entire point of canonicalization.
	a, err := SubjectDigest("fs.write", json.RawMessage(`{"path":"/tmp/x","content":"hi"}`))
	if err != nil {
		t.Fatalf("SubjectDigest() error: %v", err)
	}
	b, err := SubjectDigest("fs.write", json.RawMessage(`  { "content" : "hi" , "path" : "/tmp/x" }  `))
	if err != nil {
		t.Fatalf("SubjectDigest() error: %v", err)
	}
	if a != b {
		t.Errorf("digests differ for reordered/whitespaced-but-equivalent arguments: %q vs %q", a, b)
	}
	if a[:7] != "sha256:" {
		t.Errorf("digest %q does not have the sha256: prefix", a)
	}

	// Different tool name, same arguments, must NOT collide — the digest
	// binds the tool identity, not just the argument values (spec §5).
	c, err := SubjectDigest("fs.delete", json.RawMessage(`{"path":"/tmp/x","content":"hi"}`))
	if err != nil {
		t.Fatalf("SubjectDigest() error: %v", err)
	}
	if a == c {
		t.Error("digest must differ when the tool name differs, even with identical arguments")
	}

	// Different argument values must not collide either.
	d, err := SubjectDigest("fs.write", json.RawMessage(`{"path":"/tmp/y","content":"hi"}`))
	if err != nil {
		t.Fatalf("SubjectDigest() error: %v", err)
	}
	if a == d {
		t.Error("digest must differ when argument values differ")
	}
}

func TestSubjectDigestMatchesHandComputedHash(t *testing.T) {
	// Pin the exact canonical form against an independently-computed SHA-256,
	// so a future refactor cannot silently change what gets signed.
	const canonical = `{"arguments":{"amount_cents":125000,"to":"acct_9f3"},"name":"transfer_funds"}`
	sum := sha256.Sum256([]byte(canonical))
	want := "sha256:" + hex.EncodeToString(sum[:])

	got, err := SubjectDigest("transfer_funds", json.RawMessage(`{"to":"acct_9f3","amount_cents":125000}`))
	if err != nil {
		t.Fatalf("SubjectDigest() error: %v", err)
	}
	if got != want {
		t.Errorf("SubjectDigest() = %q, want %q (canonical form: %s)", got, want, canonical)
	}
}

func TestSubjectDigestPreservesLargeNumberLiterals(t *testing.T) {
	// A naive float64 decode would corrupt an integer this large. UseNumber()
	// must carry the literal text through untouched.
	a, err := SubjectDigest("charge", json.RawMessage(`{"amount":9007199254740993}`))
	if err != nil {
		t.Fatalf("SubjectDigest() error: %v", err)
	}
	b, err := SubjectDigest("charge", json.RawMessage(`{"amount":9007199254740992}`))
	if err != nil {
		t.Fatalf("SubjectDigest() error: %v", err)
	}
	if a == b {
		t.Error("digests for two distinct large integers collided — number precision was lost")
	}
}

func TestSubjectDigestEmptyArgumentsIsWellDefined(t *testing.T) {
	a, err := SubjectDigest("noop", nil)
	if err != nil {
		t.Fatalf("SubjectDigest(nil) error: %v", err)
	}
	b, err := SubjectDigest("noop", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("SubjectDigest({}) error: %v", err)
	}
	if a != b {
		t.Errorf("nil arguments should digest the same as an explicit empty object: %q vs %q", a, b)
	}
}

func TestSubjectDigestRejectsMalformedArguments(t *testing.T) {
	if _, err := SubjectDigest("fs.write", json.RawMessage(`{not valid json`)); err == nil {
		t.Error("SubjectDigest() with malformed arguments succeeded, want error")
	}
}

// TestVerifyDecisionNeverApprovesWithoutFullVerification is a direct check
// on the fail-closed invariant: across every rejected case above, approved
// must be false. This test exists so that invariant is asserted once,
// explicitly, rather than left implicit in each case's assertions.
func TestVerifyDecisionNeverApprovesWithoutFullVerification(t *testing.T) {
	approver := newTestApprover(t)
	digest := "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"

	cases := []DecisionResponse{
		approver.sign("hg_1", "denied", digest),
		approver.sign("hg_1", "", digest),
		approver.sign("hg_1", "approved", "sha256:wrong"),
		{RequestID: "hg_1", Decision: "approved", SubjectDigest: digest, Signature: ""},
		// Validly signed, right digest, wrong gate.
		approver.sign("hg_2", "approved", digest),
	}
	for i, resp := range cases {
		if approved, _, _ := VerifyDecision(approver.did, "hg_1", digest, resp); approved {
			t.Errorf("case %d: approved = true, want false for %+v", i, resp)
		}
	}
}
