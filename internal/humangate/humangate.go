// Package humangate implements both halves of the human-gates webhook
// decision channel that spec/human-gates-webhook.md defines: computing the
// subject_digest a request is built around (§4-§5), and verifying a
// decision response against it (§6-§8).
//
// Verification (VerifyDecision) never recomputes a digest — it only
// compares the response's echoed request_id and subject_digest against the
// ones already sent, byte for byte (§7 steps 4-5) — so SubjectDigest has
// exactly one caller in this codebase: whatever builds the outbound request,
// which is also what holds the request_id both halves are checked against.
package humangate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
// ReasonDigestMismatch maps to audit.EventGateDigestMismatch,
// ReasonRequestIDMismatch maps to audit.EventGateRequestIDMismatch, and every
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

	// ReasonRequestIDMismatch means the signature verified, but the decision
	// answers a different gate than the one being verified. Signature coverage
	// alone does not catch this: request_id is inside the signed payload, so a
	// decision genuinely signed for request A verifies perfectly as bytes — it
	// is only wrong relative to request B, which nothing but an explicit
	// comparison against the request_id actually sent can establish.
	ReasonRequestIDMismatch Reason = "request_id_mismatch"

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
//  4. Confirm resp.RequestID matches expectedRequestID (the request_id
//     Constle minted for this gate).
//  5. Confirm resp.SubjectDigest matches expectedSubjectDigest (the digest
//     Constle sent in the request).
//  6. Only if 3, 4 and 5 succeed, and resp.Decision == "approved", is the
//     call approved.
//
// Steps 4 and 5 are separate checks answering separate questions, and
// neither is implied by step 3. The signed payload covers request_id and
// subject_digest both, so a valid signature only proves the approver said
// this about that request_id and that digest — not that either one is the
// one this call is waiting on. Both bindings have to be asserted against
// what was actually sent:
//
//   - Without step 5, a decision signed over a different tool call is
//     accepted for this one.
//   - Without step 4, a decision signed for a different gate is accepted for
//     this one whenever the two share a subject_digest — which any two
//     invocations of the same tool with the same arguments do, by
//     construction (SubjectDigest is a pure function of name and arguments).
//     That makes a single approval of a repeatable call replayable into every
//     later occurrence of it, and one human "yes" would silently answer every
//     identical gate that follows. request_id is what distinguishes those
//     occurrences, so it is checked here rather than left to the fact that
//     the decision was fetched from a request_id-derived URL: a verification
//     function that fails closed cannot depend on how its input was obtained.
//
// approved is true on exactly one path: every check above passed. There is
// no code path that returns approved == true alongside a non-nil err, and no
// path that treats a decode failure, a bad signature, a request_id mismatch,
// a digest mismatch, or an unrecognized decision value as approval — an
// unverifiable or malformed decision always denies.
//
// approverPubkey is decoded fresh on every call rather than trusted from a
// cache: pkg/manifest.validateHumanGates already rejects a malformed
// approver_pubkey at `constle validate` time, but a value that becomes
// invalid between validate and run (a hand-edited Agentfile, e.g.) must
// still fail closed at the point it is actually used, not silently pass.
func VerifyDecision(approverPubkey, expectedRequestID, expectedSubjectDigest string, resp DecisionResponse) (approved bool, reason Reason, err error) {
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

	if resp.RequestID != expectedRequestID {
		return false, ReasonRequestIDMismatch, fmt.Errorf(
			"decision request_id %q does not match the request's %q", resp.RequestID, expectedRequestID)
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
// (steps 4-5) to check that the request_id and digest signed over are
// actually this gate's. Building the payload from the response's own fields
// is what makes those later comparisons load-bearing: substituting the
// expected values here would make any response verify against itself.
func signedPayload(requestID, decision, subjectDigest string) []byte {
	return []byte(requestID + "." + decision + "." + subjectDigest)
}

// SubjectDigest computes spec §5's subject_digest: SHA-256 of a canonical
// JSON encoding of {"name": toolName, "arguments": <rawArguments>} — object
// keys sorted at every level, no insignificant whitespace — hex-encoded and
// prefixed "sha256:". This is what the approver is actually signing off on
// (§4), so it must be reproducible from the tool call alone.
//
// The canonicalization relies on two guarantees encoding/json already gives:
// Marshal always emits map keys in sorted order, and decoding with
// UseNumber() carries each number's original literal text through the
// round-trip untouched, rather than the lossy float64 default. The one
// documented gap from a fully general canonicalization: object keys are
// ordered by Go's byte-wise UTF-8 comparison rather than UTF-16 code-unit
// order: these agree for every key made of Basic-Multilingual-Plane
// characters — in practice, every real MCP tool argument name — and diverge
// only for keys containing characters outside it.
func SubjectDigest(toolName string, rawArguments json.RawMessage) (string, error) {
	args := rawArguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}

	dec := json.NewDecoder(bytes.NewReader(args))
	dec.UseNumber()
	var argsValue any
	if err := dec.Decode(&argsValue); err != nil {
		return "", fmt.Errorf("tool call arguments are not valid JSON: %w", err)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]any{"name": toolName, "arguments": argsValue}); err != nil {
		return "", fmt.Errorf("cannot canonicalize tool call: %w", err)
	}
	canonical := bytes.TrimRight(buf.Bytes(), "\n") // Encode appends a trailing newline

	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
