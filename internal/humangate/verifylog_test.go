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

// TestVerifyDecisionsEvidenceFreeApprovalAlwaysFails is the review finding
// that killed the earlier heuristic. An approval with no recorded decision
// used to be reported only when some OTHER entry in the same log carried
// evidence — so a log with the evidence stripped from every approval was
// byte-for-byte the shape that heuristic read as "written by an older
// constle", and passed. An absence of proof cannot be excused by the absence
// being thorough.
func TestVerifyDecisionsEvidenceFreeApprovalAlwaysFails(t *testing.T) {
	a := newTestApprover(t)
	approval := logEntry(t, audit.EventGateApproved, map[string]any{
		"tool": "send_email", "subject_digest": testDigest, DetailDecidedBy: DecidedByWebhook})

	// Alone in the log, pinned or not.
	for _, pinned := range []string{a.did, ""} {
		rep := mustVerify(t, []audit.Entry{approval}, pinned)
		if rep.OK() {
			t.Errorf("an evidence-free approval passed (pinned=%q)", pinned)
		}
	}

	// And alongside entries that would once have made it look like an old log.
	rep := mustVerify(t, []audit.Entry{approval, approval}, a.did)
	if len(rep.Failures) != 2 {
		t.Errorf("Failures = %d, want 2 — every unproven approval counts", len(rep.Failures))
	}
	if got := failureText(rep); !strings.Contains(got, "before spec 0.4.0") {
		t.Errorf("failure does not explain the pre-0.4.0 case: %s", got)
	}
}

// TestVerifyDecisionsEvidenceFreeDenialIsNotAFailure keeps the asymmetry the
// rule above depends on: a webhook denial needs no signature to justify
// having blocked a call, and two such denials are reachable by design when
// the request cannot even be built.
func TestVerifyDecisionsEvidenceFreeDenialIsNotAFailure(t *testing.T) {
	entries := []audit.Entry{
		logEntry(t, audit.EventGateDenied, map[string]any{
			"tool": "send_email", "subject_digest": testDigest, DetailDecidedBy: DecidedByWebhook}),
		logEntry(t, audit.EventGateSignatureInvalid, map[string]any{
			"tool": "send_email", "subject_digest": testDigest, DetailDecidedBy: DecidedByWebhook}),
	}
	if rep := mustVerify(t, entries, ""); !rep.OK() {
		t.Errorf("an evidence-free webhook denial was reported as a failure: %s", failureText(rep))
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
	if !rep.OK() || rep.Verified != 0 {
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

// TestVerifyDecisionsCatchesPartialTransplant: a decision record pasted onto
// an entry it does not belong to leaves the entry's own tool name and the
// recorded request naming different calls.
func TestVerifyDecisionsCatchesPartialTransplant(t *testing.T) {
	a := newTestApprover(t)
	rec := decided(a, "hg_gate1", "approved", testDigest)
	rec.Request.ToolName = "send_email"

	e := gateEntry(t, audit.EventGateApproved, testDigest, rec)
	e.Details["tool"] = "delete_everything" // only the outer label rewritten

	rep := mustVerify(t, []audit.Entry{e}, a.did)
	if rep.OK() {
		t.Fatal("a decision pasted onto another entry passed verification")
	}
	if got := failureText(rep); !strings.Contains(got, "delete_everything") {
		t.Errorf("failure did not name the mismatched tool: %s", got)
	}
}

// TestVerifyDecisionsCannotBindToolNameToDigest pins a LIMITATION, not a
// feature, so that nobody later reads a clean report as proof of something
// it does not check.
//
// The §6 signature commits to subject_digest, and the digest commits to the
// tool name and the arguments together (§5). Recomputing it needs the
// arguments, which §9 excludes on purpose because they carry secrets. So a
// runtime that rewrites the recorded request AND the entry's own tool name
// together — keeping the captured digest and signature — produces a record
// that verifies: the approver really did sign that digest, just for a
// different call than the log now names.
//
// This is spec §10's fourth limitation. Closing it inside the log would mean
// recording the arguments. What settles it instead is the request_id
// recorded alongside, which the approver's own endpoint can match against
// what it was actually shown.
func TestVerifyDecisionsCannotBindToolNameToDigest(t *testing.T) {
	a := newTestApprover(t)
	rec := decided(a, "hg_gate1", "approved", testDigest)
	rec.Request.ToolName = "delete_everything"

	e := gateEntry(t, audit.EventGateApproved, testDigest, rec)
	e.Details["tool"] = "delete_everything"

	rep := mustVerify(t, []audit.Entry{e}, a.did)
	if !rep.OK() {
		t.Fatalf("expected the documented limitation, got failures: %s", failureText(rep))
	}
	if rep.Verified != 1 {
		t.Errorf("Verified = %d, want 1", rep.Verified)
	}
	// If this ever starts failing, the limitation was closed — update
	// spec §10 and this test together rather than deleting the test.
}

// TestResponseRecordOmitsAbsentDecidedAt: a response that sent no decided_at
// must be recorded as having sent none, not as having claimed the year 1.
func TestResponseRecordOmitsAbsentDecidedAt(t *testing.T) {
	rec := NewResponseRecord(DecisionResponse{RequestID: "hg_1", Decision: "approved"})
	if rec.DecidedAt != nil {
		t.Errorf("DecidedAt = %v, want nil for a response that sent none", rec.DecidedAt)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	if strings.Contains(string(b), "decided_at") {
		t.Errorf("absent decided_at was still recorded: %s", b)
	}
}

// TestVerifyDecisionsProvenanceCannotBeDeclined: the exemption for an
// evidence-free approval is an explicit `decided_by: terminal` and nothing
// else. An earlier revision demanded evidence only when the field read
// exactly "webhook", so the same writer that omitted the evidence could
// also decline to state provenance and pass.
func TestVerifyDecisionsProvenanceCannotBeDeclined(t *testing.T) {
	a := newTestApprover(t)
	base := func() map[string]any {
		return map[string]any{"tool": "send_email", "subject_digest": testDigest}
	}

	for _, tc := range []struct {
		name      string
		decidedBy any // nil means the field is absent entirely
	}{
		{"absent", nil},
		{"unknown value", "orchestrator"},
		{"empty string", ""},
		{"misspelled", "webhooks"},
		{"wrong case", "Terminal"},
		{"not a string", 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := base()
			if tc.decidedBy != nil {
				d[DetailDecidedBy] = tc.decidedBy
			}
			rep := mustVerify(t, []audit.Entry{logEntry(t, audit.EventGateApproved, d)}, a.did)
			if rep.OK() {
				t.Error("an evidence-free approval passed by not stating its provenance")
			}
		})
	}

	// Only the explicit terminal case is exempt, and it must stay exempt:
	// spec §8.3 says a terminal approval signs nothing to re-verify.
	d := base()
	d[DetailDecidedBy] = DecidedByTerminal
	if rep := mustVerify(t, []audit.Entry{logEntry(t, audit.EventGateApproved, d)}, a.did); !rep.OK() {
		t.Errorf("an explicit terminal approval was reported as a failure: %s", failureText(rep))
	}
}

// TestVerifyDecisionsCrossChecksRequireTheirFields: the two comparisons that
// hold a decision to the call the entry names used to run only when both
// sides were present, so deleting either side removed the check and let a
// captured decision be attached to a different call.
func TestVerifyDecisionsCrossChecksRequireTheirFields(t *testing.T) {
	a := newTestApprover(t)

	build := func(t *testing.T, mutate func(details map[string]any, request map[string]any)) audit.Entry {
		t.Helper()
		rec := decided(a, "hg_1", "approved", testDigest)
		rec.Request.ToolName = "send_email"
		e := gateEntry(t, audit.EventGateApproved, testDigest, rec)
		e.Details["tool"] = "send_email"
		req, _ := e.Details[DetailDecisionRequest].(map[string]any)
		if req == nil {
			t.Fatal("decision_request did not survive the round trip as a map")
		}
		mutate(e.Details, req)
		return e
	}

	for _, tc := range []struct {
		name   string
		mutate func(details, request map[string]any)
	}{
		{"record drops tool_name", func(_, r map[string]any) { delete(r, "tool_name") }},
		{"entry drops tool", func(d, _ map[string]any) { delete(d, "tool") }},
		{"record drops subject_digest", func(_, r map[string]any) { delete(r, "subject_digest") }},
		{"entry drops subject_digest", func(d, _ map[string]any) { delete(d, "subject_digest") }},
		{"entry tool emptied", func(d, _ map[string]any) { d["tool"] = "" }},
		{"record tool_name emptied", func(_, r map[string]any) { r["tool_name"] = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := mustVerify(t, []audit.Entry{build(t, tc.mutate)}, a.did)
			if rep.OK() {
				t.Error("a decision passed with one side of a cross-check removed")
			}
			if rep.Verified != 0 {
				t.Errorf("Verified = %d, want 0", rep.Verified)
			}
			// Assert the presence rule is what rejected it. Without this,
			// the record-side cases pass for the wrong reason — a deleted
			// digest also breaks the signature comparison downstream, so
			// the subtest would still go green with the presence rule gone.
			if got := failureText(rep); !strings.Contains(got, "nothing") &&
				!strings.Contains(got, "cannot be tied") {
				t.Errorf("rejected for some other reason than the missing field: %s", got)
			}
		})
	}

	// The unmutated entry must still verify, or the test above proves nothing.
	rep := mustVerify(t, []audit.Entry{build(t, func(map[string]any, map[string]any) {})}, a.did)
	if !rep.OK() || rep.Verified != 1 {
		t.Errorf("an intact decision stopped verifying: %s", failureText(rep))
	}
}

// TestVerifyDecisionsBoundsTheVerdictLine reproduces the focused review's
// finding: EvidenceFieldMax is enforced by NewResponseRecord when a record
// is WRITTEN, and a log under examination arrives already written — by
// whoever wrote it. A 1 MiB field in an attacker-authored log produced a
// verdict line of the same size.
func TestVerifyDecisionsBoundsTheVerdictLine(t *testing.T) {
	a := newTestApprover(t)
	huge := "sha256:" + strings.Repeat("a", 1<<20)

	// The entry and its recorded request name different subjects, which is
	// the path that interpolates both of them into one line.
	rec := decided(a, "hg_1", "approved", testDigest)
	rec.Request.SubjectDigest = huge
	e := gateEntry(t, audit.EventGateApproved, testDigest, rec)

	rep := mustVerify(t, []audit.Entry{e}, a.did)
	if rep.OK() {
		t.Fatal("mismatched subject digests passed verification")
	}
	line := rep.Failures[0].String()
	if len(line) > problemDetailMax+512 {
		t.Errorf("verdict line is %d bytes for a %d-byte field — not bounded", len(line), len(huge))
	}
	if !strings.Contains(line, "bytes in all") {
		t.Errorf("truncation was not reported, so a clipped value reads as a short one: %q", line)
	}
}

// TestVerifyDecisionsBoundsEveryDetailConstituent walks the other values
// that reach a detail line off an entry, so the bound is not resting on one
// code path having been found.
func TestVerifyDecisionsBoundsEveryDetailConstituent(t *testing.T) {
	a := newTestApprover(t)
	huge := strings.Repeat("Z", 1<<20)

	for _, tc := range []struct {
		name  string
		build func() audit.Entry
	}{
		{"approver_pubkey", func() audit.Entry {
			rec := decided(a, "hg_1", "approved", testDigest)
			rec.ApproverPubkey = huge
			return gateEntry(t, audit.EventGateApproved, testDigest, rec)
		}},
		{"tool name", func() audit.Entry {
			rec := decided(a, "hg_1", "approved", testDigest)
			rec.Request.ToolName = huge
			return gateEntry(t, audit.EventGateApproved, testDigest, rec)
		}},
		{"event", func() audit.Entry {
			rec := decided(a, "hg_1", "approved", testDigest)
			e := gateEntry(t, audit.EventGateApproved, testDigest, rec)
			e.Event = audit.EventType(huge)
			return e
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := mustVerify(t, []audit.Entry{tc.build()}, a.did)
			if rep.OK() {
				t.Fatal("the oversized entry passed verification")
			}
			if line := rep.Failures[0].String(); len(line) > problemDetailMax+512 {
				t.Errorf("verdict line is %d bytes — not bounded", len(line))
			}
		})
	}
}

// TestProblemDetailBoundSurvivesAnExternalCaller: String is exported, so a
// DecisionProblem can be built by a caller that never went through
// VerifyDecisions and never met boundedArgs.
func TestProblemDetailBoundSurvivesAnExternalCaller(t *testing.T) {
	p := DecisionProblem{Entry: 1, Event: audit.EventGateApproved, Detail: strings.Repeat("q", 1<<20)}
	if line := p.String(); len(line) > problemDetailMax+512 {
		t.Errorf("verdict line is %d bytes — the backstop bound did not apply", len(line))
	}
}

// TestProblemDetailKeepsConstleOwnProse: the bound must not clip the
// sentences constle writes, or the fix trades one defect for another.
func TestProblemDetailKeepsConstleOwnProse(t *testing.T) {
	p := DecisionProblem{Entry: 1, Event: audit.EventGateApproved, Detail: unprovenApproval}
	if line := p.String(); strings.Contains(line, "bytes in all") {
		t.Errorf("the longest legitimate detail was truncated: %q", line)
	}
}

// TestVerifyDecisionsBoundsTheDetailItself isolates boundedArgs from the
// 1024-byte backstop in String(). With only the backstop, a Detail composed
// from a megabyte-long log field is still a megabyte long in memory and is
// merely clipped on the way to the screen — every consumer that reads the
// field directly still carries it.
func TestVerifyDecisionsBoundsTheDetailItself(t *testing.T) {
	a := newTestApprover(t)
	rec := decided(a, "hg_1", "approved", testDigest)
	rec.Request.SubjectDigest = "sha256:" + strings.Repeat("a", 1<<20)

	rep := mustVerify(t, []audit.Entry{gateEntry(t, audit.EventGateApproved, testDigest, rec)}, a.did)
	if rep.OK() {
		t.Fatal("mismatched subject digests passed verification")
	}
	if n := len(rep.Failures[0].Detail); n > problemDetailMax {
		t.Errorf("Detail is %d bytes before rendering — the constituents were not bounded", n)
	}
}
