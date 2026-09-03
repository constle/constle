package humangate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

	approved, reason, err := VerifyDecision(approver.did, digest, resp)
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

	approved, reason, err := VerifyDecision(approver.did, digest, resp)
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

	approved, reason, err := VerifyDecision(approver.did, digest, resp)
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

	approved, reason, err := VerifyDecision(approver.did, digest, resp)
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

	approved, reason, err := VerifyDecision(approver.did, sentDigest, resp)
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

func TestVerifyDecisionMalformedOrMissingDecisionRejected(t *testing.T) {
	approver := newTestApprover(t)
	digest := "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"

	for _, decision := range []string{"denied", "", "Approved", "approved ", "maybe"} {
		resp := approver.sign("hg_7f3a9c2e", decision, digest)

		approved, reason, err := VerifyDecision(approver.did, digest, resp)
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
		approved, reason, err := VerifyDecision(badKey, digest, resp)
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
	}
	for i, resp := range cases {
		if approved, _, _ := VerifyDecision(approver.did, digest, resp); approved {
			t.Errorf("case %d: approved = true, want false for %+v", i, resp)
		}
	}
}
