// Package humangate implements the verification half of the human-gates
// webhook decision channel (spec/human-gates-webhook.md §6-§8): given a
// decision response and the Agentfile's declared approver_pubkey, it decides
// whether a gated MCP tool call may proceed.
//
// It deliberately does not implement §4-§5 (building and delivering the
// outbound request, including the canonical subject-digest encoding) — the
// spec itself flags that half as an open design question (§5's note on JCS
// vs. raw-byte canonicalization) not yet settled, and the transport/delivery
// mechanism as explicitly out of scope for this revision (§4). Verification
// needs neither: it only compares the response's echoed subject_digest
// against the digest Constle already sent, byte for byte (§7 step 4).
package humangate

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/constle/constle/pkg/did"
)

// DecisionApproved is the only Decision value that can result in a gated
// call proceeding (spec §6, §8). Any other value — including "denied",
// empty, or a typo — is denied.
const DecisionApproved = "approved"

// DecisionResponse is the wire format of the decision that comes back from
// the human-gates decision endpoint (spec §6).
//
// Signature is encoded as base64 (encoding/base64, StdEncoding) over the
// bytes RequestID + "." + Decision + "." + SubjectDigest. This matches the
// encoding audit.Entry.Sig and a2a.Envelope.Sig already use for every other
// Ed25519 signature field in this codebase, rather than introducing a third,
// did:key-flavored (multibase base58btc) convention for signatures alone —
// approver_pubkey uses did:key because pkg/did already speaks that format
// for public keys; nothing here calls for extending it to signatures too.
type DecisionResponse struct {
	RequestID     string    `json:"request_id"`
	Decision      string    `json:"decision"`
	SubjectDigest string    `json:"subject_digest"`
	Signature     string    `json:"signature"`
	DecidedAt     time.Time `json:"decided_at"`
}

// Reason explains a VerifyDecision outcome. It exists so a caller can pick
// the exact audit event the fail-closed table (spec §8) calls for:
// ReasonSignatureInvalid maps to audit.EventGateSignatureInvalid,
// ReasonDigestMismatch maps to audit.EventGateDigestMismatch, and every
// other non-approved reason maps to the existing audit.EventGateDenied.
type Reason string

const (
	// ReasonApproved is the only reason paired with approved == true.
	ReasonApproved Reason = "approved"

	// ReasonSignatureInvalid covers both an undecodable approver_pubkey or
	// signature, and a signature that decodes but does not verify. The spec's
	// fail-closed table does not distinguish these — both mean "this decision
	// cannot be attributed to the declared approver."
	ReasonSignatureInvalid Reason = "signature_invalid"

	// ReasonDigestMismatch means the signature verified, but the digest it
	// was computed over is not the digest of the tool call actually sent —
	// a genuinely signed statement about the wrong thing.
	ReasonDigestMismatch Reason = "digest_mismatch"

	// ReasonNotApproved covers a missing, malformed, or explicit "denied"
	// decision value once signature and digest have both checked out.
	ReasonNotApproved Reason = "not_approved"
)

// VerifyDecision implements spec §7's verification steps in order, exactly
// as the §8 fail-closed table specifies:
//
//  1. Decode approverPubkey (the Agentfile's human_gates.approver_pubkey).
//  2. Reconstruct the signed payload from the response's own fields.
//  3. Verify Signature against that payload with the decoded public key.
//  4. Confirm resp.SubjectDigest matches expectedSubjectDigest (the digest
//     Constle sent in the request).
//  5. Only if 3 and 4 succeed, and resp.Decision == "approved", is the call
//     approved.
//
// approved is true on exactly one path: every check above passed. There is
// no code path that returns approved == true alongside a non-nil err, and no
// path that treats a decode failure, a bad signature, a digest mismatch, or
// an unrecognized decision value as approval — an unverifiable or malformed
// decision always denies.
//
// approverPubkey is decoded fresh on every call rather than trusted from a
// cache: pkg/manifest.validateHumanGates already rejects a malformed
// approver_pubkey at `constle validate` time, but a value that becomes
// invalid between validate and run (a hand-edited Agentfile, e.g.) must
// still fail closed at the point it is actually used, not silently pass.
func VerifyDecision(approverPubkey, expectedSubjectDigest string, resp DecisionResponse) (approved bool, reason Reason, err error) {
	pub, err := did.PublicKey(approverPubkey)
	if err != nil {
		return false, ReasonSignatureInvalid, fmt.Errorf("approver_pubkey is not a valid did:key Ed25519 string: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return false, ReasonSignatureInvalid, fmt.Errorf("decision signature is not valid base64: %w", err)
	}

	payload := signedPayload(resp.RequestID, resp.Decision, resp.SubjectDigest)
	if !ed25519.Verify(pub, payload, sig) {
		return false, ReasonSignatureInvalid, errors.New("decision signature does not verify against approver_pubkey")
	}

	if resp.SubjectDigest != expectedSubjectDigest {
		return false, ReasonDigestMismatch, fmt.Errorf(
			"decision subject_digest %q does not match the request's %q", resp.SubjectDigest, expectedSubjectDigest)
	}

	if resp.Decision != DecisionApproved {
		return false, ReasonNotApproved, nil
	}

	return true, ReasonApproved, nil
}

// signedPayload reconstructs the exact bytes the approver signs (spec §6):
// request_id + "." + decision + "." + subject_digest, ASCII period
// separators, taken verbatim from the response's own fields (spec §7 step
// 2) — never from the original request, which is only consulted afterward
// (step 4) to check the digest actually matches.
func signedPayload(requestID, decision, subjectDigest string) []byte {
	return []byte(requestID + "." + decision + "." + subjectDigest)
}
