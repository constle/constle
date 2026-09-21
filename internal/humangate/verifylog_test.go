package humangate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/constle/constle/internal/audit"
)

const testDigest = "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"

// logEntry builds one audit entry the way a verifier meets it: details
// encoded to JSON by the gate and decoded back to generic maps.
func logEntry(t *testing.T, event audit.EventType, details map[string]any) audit.Entry {
	t.Helper()
	return audit.Entry{Event: event, Details: roundTrip(t, details)}
}

// gateEntry assembles a terminal gate entry exactly as mcpgate.runGate does:
// the gate's own view of the subject, the source that decided, and the §9
// evidence merged in.
func gateEntry(t *testing.T, event audit.EventType, digest string, rec *RecordedDecision) audit.Entry {
	t.Helper()
	details := map[string]any{
		"tool":           "fs.write",
		"server":         "files",
		"subject_digest": digest,
		DetailDecidedBy:  DecidedByWebhook,
		"wait_ms":        1840,
	}
	for k, v := range rec.Details() {
		details[k] = v
	}
	return logEntry(t, event, details)
}

// decided builds the evidence for a decision the approver really signed.
func decided(a testApprover, requestID, decision, digest string) *RecordedDecision {
	resp := NewResponseRecord(a.sign(requestID, decision, digest))
	return &RecordedDecision{
		Request: RequestRecord{
			RequestID:     requestID,
			AgentName:     "invoice-processor",
			ToolName:      "fs.write",
			SubjectDigest: digest,
			Timestamp:     time.Now().UTC(),
		},
		Response:       &resp,
		ApproverPubkey: a.did,
	}
}

func mustVerify(t *testing.T, entries []audit.Entry, pinned string) *DecisionReport {
	t.Helper()
	rep, err := VerifyDecisions(entries, pinned)
	if err != nil {
		t.Fatalf("VerifyDecisions() error: %v", err)
	}
	return rep
}

// failureText joins every failure so a test can assert on what was reported
// without depending on ordering.
func failureText(rep *DecisionReport) string {
	var b strings.Builder
	for _, f := range rep.Failures {
		b.WriteString(f.String())
		b.WriteString("\n")
	}
	return b.String()
}

func TestVerifyDecisionsGenuineApproval(t *testing.T) {
	a := newTestApprover(t)
	entries := []audit.Entry{gateEntry(t, audit.EventGateApproved, testDigest, decided(a, "hg_1", "approved", testDigest))}

	rep := mustVerify(t, entries, a.did)
	if !rep.OK() {
		t.Fatalf("a genuine approval failed verification: %s", failureText(rep))
	}
	if rep.Verified != 1 {
		t.Errorf("Verified = %d, want 1", rep.Verified)
	}
}

// TestVerifyDecisionsUnprovenApproval is HG02 itself: a log that says the
// webhook approver let a call through, with nothing recorded that could show
// it did. Before spec 0.4.0 every webhook approval looked like this.
func TestVerifyDecisionsUnprovenApproval(t *testing.T) {
	a := newTestApprover(t)
	entries := []audit.Entry{
		// One provable approval establishes that this log records evidence...
		gateEntry(t, audit.EventGateApproved, testDigest, decided(a, "hg_1", "approved", testDigest)),
		// ...so a second approval without any is a real gap, not an old log.
		logEntry(t, audit.EventGateApproved, map[string]any{
			"tool": "fs.write", "subject_digest": testDigest, DetailDecidedBy: DecidedByWebhook,
		}),
	}

	rep := mustVerify(t, entries, a.did)
	if rep.OK() {
		t.Fatal("an approval with no recorded decision passed verification")
	}
	if got := failureText(rep); !strings.Contains(got, "no signed decision is recorded") {
		t.Errorf("failure did not name the missing decision: %s", got)
	}
}

// TestVerifyDecisionsForgedApproval: the log claims an approval, and a
// decision is recorded, but the signature is not the approver's.
func TestVerifyDecisionsForgedApproval(t *testing.T) {
	real, impostor := newTestApprover(t), newTestApprover(t)

	rec := decided(impostor, "hg_1", "approved", testDigest)
	rec.ApproverPubkey = real.did // the log claims the real approver signed it

	rep := mustVerify(t, []audit.Entry{gateEntry(t, audit.EventGateApproved, testDigest, rec)}, real.did)
	if rep.OK() {
		t.Fatal("an approval signed by the wrong key passed verification")
	}
	if got := failureText(rep); !strings.Contains(got, string(ReasonSignatureInvalid)) {
		t.Errorf("failure did not name the bad signature: %s", got)
	}
}

// TestVerifyDecisionsMisattributedRejection is the other direction, and the
// reason the check compares against the event rather than just verifying:
// an entry that blames the approver for a bad signature, while the decision
// it recorded verifies perfectly, is misreporting what happened.
func TestVerifyDecisionsMisattributedRejection(t *testing.T) {
	a := newTestApprover(t)
	rec := decided(a, "hg_1", "approved", testDigest)

	rep := mustVerify(t, []audit.Entry{gateEntry(t, audit.EventGateSignatureInvalid, testDigest, rec)}, a.did)
	if rep.OK() {
		t.Fatal("gate_signature_invalid carrying a valid decision passed verification")
	}
	if got := failureText(rep); !strings.Contains(got, string(audit.EventGateSignatureInvalid)) {
		t.Errorf("failure did not name the mismatched event: %s", got)
	}
}

// TestVerifyDecisionsRejectedDecisionsReproduce: the three fail-closed
// events each record the decision that caused them, and each must re-verify
// as exactly that failure — the evidence explains the denial rather than
// looking like a new one.
func TestVerifyDecisionsRejectedDecisionsReproduce(t *testing.T) {
	a := newTestApprover(t)
	otherDigest := "sha256:dead00000000000000000000000000000000000000000000000000000000beef"

	t.Run("request_id mismatch", func(t *testing.T) {
		rec := decided(a, "hg_other", "approved", testDigest)
		rec.Request.RequestID = "hg_1" // what this gate actually sent
		rep := mustVerify(t, []audit.Entry{
			gateEntry(t, audit.EventGateRequestIDMismatch, testDigest, rec)}, a.did)
		if !rep.OK() {
			t.Errorf("recorded request_id mismatch did not reproduce: %s", failureText(rep))
		}
		if rep.Verified != 1 {
			t.Errorf("Verified = %d, want 1 — the recorded decision must actually be checked", rep.Verified)
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		rec := decided(a, "hg_1", "approved", otherDigest)
		rec.Request.SubjectDigest = testDigest
		rep := mustVerify(t, []audit.Entry{
			gateEntry(t, audit.EventGateDigestMismatch, testDigest, rec)}, a.did)
		if !rep.OK() {
			t.Errorf("recorded digest mismatch did not reproduce: %s", failureText(rep))
		}
		if rep.Verified != 1 {
			t.Errorf("Verified = %d, want 1 — the recorded decision must actually be checked", rep.Verified)
		}
	})

	t.Run("plain denial", func(t *testing.T) {
		rec := decided(a, "hg_1", "denied", testDigest)
		rep := mustVerify(t, []audit.Entry{
			gateEntry(t, audit.EventGateDenied, testDigest, rec)}, a.did)
		if !rep.OK() {
			t.Errorf("recorded denial did not reproduce: %s", failureText(rep))
		}
		if rep.Verified != 1 {
			t.Errorf("Verified = %d, want 1 — a signed denial is evidence too", rep.Verified)
		}
	})
}

// TestVerifyDecisionsPinnedKeyMismatch: recording approver_pubkey is what
// makes a swapped approver key visible. Without pinning, the entry verifies
// cleanly against the key it names.
func TestVerifyDecisionsPinnedKeyMismatch(t *testing.T) {
	trusted, swapped := newTestApprover(t), newTestApprover(t)
	entries := []audit.Entry{gateEntry(t, audit.EventGateApproved, testDigest,
		decided(swapped, "hg_1", "approved", testDigest))}

	if rep := mustVerify(t, entries, ""); !rep.OK() {
		t.Errorf("unpinned verification should accept the key the log names: %s", failureText(rep))
	}

	rep := mustVerify(t, entries, trusted.did)
	if rep.OK() {
		t.Fatal("a decision verified against a swapped approver key passed a pinned check")
	}
	if got := failureText(rep); !strings.Contains(got, "not the pinned") {
		t.Errorf("failure did not name the key swap: %s", got)
	}
}

// TestVerifyDecisionsTruncatedIsNotForgery: a record the runtime's own bloat
// defence clipped must be reported as unverifiable, not as a bad signature —
// the bytes were dropped here, not forged there.
func TestVerifyDecisionsTruncatedIsNotForgery(t *testing.T) {
	a := newTestApprover(t)
	rec := decided(a, "hg_1", "approved", testDigest)
	rec.Response.Signature = strings.Repeat("A", EvidenceFieldMax)
	rec.Response.Truncated = true

	rep := mustVerify(t, []audit.Entry{gateEntry(t, audit.EventGateApproved, testDigest, rec)}, a.did)
	if rep.OK() {
		t.Fatal("a truncated decision passed verification")
	}
	got := failureText(rep)
	if !strings.Contains(got, "truncated") {
		t.Errorf("failure did not name the truncation: %s", got)
	}
	if strings.Contains(got, string(ReasonSignatureInvalid)) {
		t.Errorf("truncation was reported as a bad signature: %s", got)
	}
}

// TestVerifyDecisionsInternalInconsistency: the entry's own subject_digest
// and the recorded request must name the same call. No signature over either
// one settles which is the real subject, so a disagreement is a failure.
func TestVerifyDecisionsInternalInconsistency(t *testing.T) {
	a := newTestApprover(t)
	rec := decided(a, "hg_1", "approved", testDigest)

	other := "sha256:dead00000000000000000000000000000000000000000000000000000000beef"
	rep := mustVerify(t, []audit.Entry{gateEntry(t, audit.EventGateApproved, other, rec)}, a.did)
	if rep.OK() {
		t.Fatal("an entry whose two halves name different calls passed verification")
	}
	if got := failureText(rep); !strings.Contains(got, "subject_digest") {
		t.Errorf("failure did not name the subject mismatch: %s", got)
	}
}

// TestVerifyDecisionsLegacyLogIsNotAFalseAlarm: a log written before spec
// 0.4.0 records no decisions anywhere. Every webhook approval in it is
// genuinely unproven, but reporting them as failures would bury a real
// finding under an alarm about software age.
func TestVerifyDecisionsLegacyLogIsNotAFalseAlarm(t *testing.T) {
	entries := []audit.Entry{
		logEntry(t, audit.EventGateApproved, map[string]any{
			"tool": "fs.write", "subject_digest": testDigest, DetailDecidedBy: DecidedByWebhook}),
		logEntry(t, audit.EventGateDenied, map[string]any{
			"tool": "fs.write", "subject_digest": testDigest, DetailDecidedBy: DecidedByWebhook}),
	}

	rep := mustVerify(t, entries, "")
	if !rep.OK() {
		t.Errorf("a pre-0.4.0 log was reported as failing: %s", failureText(rep))
	}
	if len(rep.Unproven) != 1 {
		t.Errorf("Unproven = %d, want 1 — the approval, not the denial", len(rep.Unproven))
	}
}

// TestVerifyDecisionsIgnoresTerminalGates: a gate answered at the terminal
// produces no signed statement, and demanding one would report every
// keyboard approval as unproven.
func TestVerifyDecisionsIgnoresTerminalGates(t *testing.T) {
	entries := []audit.Entry{
		logEntry(t, audit.EventGateApproved, map[string]any{
			"tool": "fs.write", "subject_digest": testDigest, DetailDecidedBy: "terminal"}),
	}
	rep := mustVerify(t, entries, "")
	if !rep.OK() || len(rep.Unproven) != 0 || rep.Verified != 0 {
		t.Errorf("a terminal-decided gate was not ignored: %+v", rep)
	}
}

// TestVerifyDecisionsUnansweredGate: a timeout records the request but no
// decision. There is nothing signed to check, and the record exists so the
// gate can be correlated with the receiver's log by request_id.
func TestVerifyDecisionsUnansweredGate(t *testing.T) {
	a := newTestApprover(t)
	rec := &RecordedDecision{
		Request:        RequestRecord{RequestID: "hg_1", ToolName: "fs.write", SubjectDigest: testDigest},
		ApproverPubkey: a.did,
	}
	details := map[string]any{"tool": "fs.write", "subject_digest": testDigest, "on_timeout": "abort"}
	for k, v := range rec.Details() {
		details[k] = v
	}

	rep := mustVerify(t, []audit.Entry{logEntry(t, audit.EventGateTimeout, details)}, a.did)
	if !rep.OK() {
		t.Fatalf("an unanswered gate was reported as a failure: %s", failureText(rep))
	}
	if rep.Unanswered != 1 {
		t.Errorf("Unanswered = %d, want 1", rep.Unanswered)
	}
}

func TestVerifyDecisionsRejectsBadPinnedKey(t *testing.T) {
	if _, err := VerifyDecisions(nil, "did:key:not-a-real-key"); err == nil {
		t.Error("VerifyDecisions() accepted an invalid pinned approver_pubkey")
	}
}

// TestVerifyDecisionsMalformedEvidence: details that cannot be read back as
// a decision are a failure, not a silent skip.
func TestVerifyDecisionsMalformedEvidence(t *testing.T) {
	e := audit.Entry{Event: audit.EventGateApproved, Details: map[string]any{
		DetailDecisionRequest: json.RawMessage(`[]`)}}
	rep := mustVerify(t, []audit.Entry{e}, "")
	if rep.OK() {
		t.Error("malformed decision evidence passed verification")
	}
}

// TestVerifyDecisionsApprovalWithRequestButNoDecision closes the same gap
// from the other side: an entry that records having ASKED the approver, and
// nothing about any answer, is still an approval nothing can prove. Reaching
// that state through a half-written record rather than through no record at
// all must not buy it a pass as an unanswered gate.
func TestVerifyDecisionsApprovalWithRequestButNoDecision(t *testing.T) {
	a := newTestApprover(t)
	rec := &RecordedDecision{
		Request:        RequestRecord{RequestID: "hg_1", ToolName: "fs.write", SubjectDigest: testDigest},
		ApproverPubkey: a.did,
	}

	rep := mustVerify(t, []audit.Entry{gateEntry(t, audit.EventGateApproved, testDigest, rec)}, a.did)
	if rep.OK() {
		t.Fatal("an approval recording only its request passed verification")
	}
	if rep.Unanswered != 0 {
		t.Errorf("Unanswered = %d, want 0 — the call ran, it was not left hanging", rep.Unanswered)
	}
	if got := failureText(rep); !strings.Contains(got, "no signed decision is recorded") {
		t.Errorf("failure did not name the missing decision: %s", got)
	}
}
