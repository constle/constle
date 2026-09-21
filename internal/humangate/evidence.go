package humangate

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// This file implements spec/human-gates-webhook.md §9: persisting a gate's
// signed decision to the audit log, and re-verifying it offline afterwards.
//
// §9 says the decision is written "verbatim". What travels to the log is the
// set of signed FIELDS, not the raw HTTP body they arrived in, and the two
// are equivalent here in a way they are not elsewhere in this codebase:
// audit.Entry and a2a.Envelope both sign their own wire bytes, so only those
// exact bytes can verify them. A §6 decision is different — signedPayload
// reconstructs request_id + "." + decision + "." + subject_digest from the
// response's parsed fields and never touches the raw body, so a record of
// those fields reproduces the signed payload exactly. Keeping the raw body
// instead would add nothing verifiable while copying an unbounded,
// endpoint-controlled blob (up to mcpgate's 64 KiB poll cap) into a signed,
// hash-chained log that is designed to travel.
//
// Spec 0.4.0 amends §9's wording to say so, and to say that the recorded
// request deliberately omits tool_call.arguments: those routinely carry
// secrets, mcpgate.runGate has always refused to copy them into the log, and
// the signature covers the digest rather than the arguments, so excluding
// them costs the offline verifier nothing.

// Audit detail keys carrying a gate's decision evidence. They live here, in
// the package that both writes and reads them, so the gate and the verifier
// cannot drift apart on a spelling.
const (
	DetailDecisionRequest  = "decision_request"
	DetailDecisionResponse = "decision_response"
	DetailApproverPubkey   = "approver_pubkey"

	// DetailDecidedBy names the existing details field recording which
	// source answered a gate, and DecidedByWebhook is its value for the
	// external decision channel. Both are constants here rather than
	// literals at the gate, because the offline verifier keys its central
	// question off them: an entry that says a webhook decided it, and
	// records no signed decision, is an approval nothing can prove.
	DetailDecidedBy  = "decided_by"
	DecidedByWebhook = "webhook"
)

// EvidenceFieldMax bounds every string copied out of a decision response
// before it reaches the audit log.
//
// Every field a real decision carries is far shorter: a request_id is "hg_"
// plus 16 hex characters, a subject_digest is "sha256:" plus 64, an Ed25519
// signature is always exactly 88 base64 characters, and a decision is one of
// two words. The cap exists for the responses that are NOT real — the ones
// recorded by gate_signature_invalid and the two mismatch events, whose
// contents an untrusted endpoint chose. Those are exactly the records worth
// keeping and exactly the bytes worth bounding, and a cap applied only to
// the response as a whole would still let one field carry all of it.
//
// Deliberately not mcpgate's clampJSONValue (64): that bound is for names
// echoed back to an agent, and it would truncate a valid signature.
const EvidenceFieldMax = 256

// RequestRecord is the identifying half of the spec §4 request Constle sent,
// as written to the audit log.
//
// tool_call.arguments is absent by design, not by omission. SubjectDigest is
// what stands in for it: the signature attests to the digest, so a verifier
// needs the digest and not the arguments, while the arguments themselves
// routinely carry secrets and payloads. The caveat runGate already documents
// applies unchanged — the digest is an unsalted SHA-256 and is recoverable
// by brute force over an enumerable argument space, so it is a forensic
// handle, not a confidentiality boundary.
type RequestRecord struct {
	RequestID     string    `json:"request_id"`
	AgentName     string    `json:"agent_name,omitempty"`
	ToolName      string    `json:"tool_name,omitempty"`
	SubjectDigest string    `json:"subject_digest,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// ResponseRecord is the spec §6 decision as written to the audit log: the
// four signed fields, plus the one unsigned field the endpoint sent.
//
// It is a separate type from DecisionResponse rather than a reuse of it, so
// that Truncated cannot be set by an endpoint that simply sends a
// "truncated" field of its own. NewResponseRecord is the only way to build
// one, which makes it the single point where endpoint-controlled bytes are
// bounded.
type ResponseRecord struct {
	RequestID     string `json:"request_id,omitempty"`
	Decision      string `json:"decision,omitempty"`
	SubjectDigest string `json:"subject_digest,omitempty"`
	Signature     string `json:"signature,omitempty"`

	// DecidedAt is the endpoint's own claim about when it decided. It is
	// NOT covered by the §6 signature, which spans exactly request_id,
	// decision and subject_digest — so it is recorded as an assertion by
	// the endpoint, never as an attested fact, and nothing verifies it.
	DecidedAt time.Time `json:"decided_at,omitempty"`

	// Truncated marks a record whose fields hit EvidenceFieldMax. Such a
	// record can no longer reproduce the signed payload, so the verifier
	// reports it as unverifiable rather than as a bad signature: the bytes
	// were dropped by this runtime's own bloat defence, not forged.
	Truncated bool `json:"truncated,omitempty"`
}

// NewResponseRecord copies a decision response into its audit form, bounding
// every endpoint-controlled field at EvidenceFieldMax.
func NewResponseRecord(resp DecisionResponse) ResponseRecord {
	rec := ResponseRecord{DecidedAt: resp.DecidedAt}
	var cut bool
	rec.RequestID, cut = clampEvidence(resp.RequestID)
	rec.Truncated = rec.Truncated || cut
	rec.Decision, cut = clampEvidence(resp.Decision)
	rec.Truncated = rec.Truncated || cut
	rec.SubjectDigest, cut = clampEvidence(resp.SubjectDigest)
	rec.Truncated = rec.Truncated || cut
	rec.Signature, cut = clampEvidence(resp.Signature)
	rec.Truncated = rec.Truncated || cut
	return rec
}

// wire rebuilds the response as VerifyDecision consumes it. A truncated
// record must never reach here — VerifyDecisions rejects those first — since
// a clipped signature would verify as forged rather than as incomplete.
func (r ResponseRecord) wire() DecisionResponse {
	return DecisionResponse{
		RequestID:     r.RequestID,
		Decision:      r.Decision,
		SubjectDigest: r.SubjectDigest,
		Signature:     r.Signature,
		DecidedAt:     r.DecidedAt,
	}
}

// clampEvidence bounds one field, dropping a partial rune rather than
// emitting a broken one (mcpgate.clampJSONValue's rule).
func clampEvidence(s string) (string, bool) {
	if len(s) <= EvidenceFieldMax {
		return s, false
	}
	return strings.ToValidUTF8(s[:EvidenceFieldMax], ""), true
}

// RecordedDecision is one gate's §9 evidence, recovered from an audit
// entry's details.
type RecordedDecision struct {
	Request        RequestRecord
	Response       *ResponseRecord // nil when the gate timed out unanswered
	ApproverPubkey string
}

// Details renders the evidence as the audit detail keys a terminal gate
// entry carries. A nil receiver contributes nothing, so a gate decided at
// the terminal — which produces no signed statement at all — keeps exactly
// the details it has always had.
func (r *RecordedDecision) Details() map[string]any {
	if r == nil {
		return nil
	}
	d := map[string]any{DetailDecisionRequest: r.Request}
	if r.Response != nil {
		d[DetailDecisionResponse] = *r.Response
	}
	if r.ApproverPubkey != "" {
		d[DetailApproverPubkey] = r.ApproverPubkey
	}
	return d
}

// RecordedDecisionFrom recovers the evidence written by Details. It returns
// (nil, nil) for an entry that carries none — every gate decided at the
// terminal, and every entry written before spec 0.4.0.
func RecordedDecisionFrom(details map[string]any) (*RecordedDecision, error) {
	raw, ok := details[DetailDecisionRequest]
	if !ok {
		return nil, nil
	}

	rec := &RecordedDecision{}
	if err := remarshal(raw, &rec.Request); err != nil {
		return nil, fmt.Errorf("%s is malformed: %w", DetailDecisionRequest, err)
	}
	if raw, ok := details[DetailDecisionResponse]; ok {
		rec.Response = &ResponseRecord{}
		if err := remarshal(raw, rec.Response); err != nil {
			return nil, fmt.Errorf("%s is malformed: %w", DetailDecisionResponse, err)
		}
	}
	if s, ok := details[DetailApproverPubkey].(string); ok {
		rec.ApproverPubkey = s
	}
	return rec, nil
}

// remarshal moves one value from a decoded details map into its struct.
// audit.Entry.Details is map[string]any by design — the log carries many
// event shapes — so a nested record comes back as a generic map and has to
// be re-encoded to land in a typed field.
func remarshal(v any, into any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}
