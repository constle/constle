package humangate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// roundTrip puts a details map through the encode/decode cycle a real audit
// log imposes: the gate writes structs into map[string]any, the file holds
// JSON, and a verifier reads generic maps back. Every test here goes through
// it, so none of them can pass on a value that would not survive the log.
func roundTrip(t *testing.T, details map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("json.Marshal(details) error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("json.Unmarshal(details) error: %v", err)
	}
	return out
}

func TestRecordedDecisionRoundTrip(t *testing.T) {
	approver := newTestApprover(t)
	digest := "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"
	resp := approver.sign("hg_7f3a9c2e", "approved", digest)
	respRec := NewResponseRecord(resp)

	rec := &RecordedDecision{
		Request: RequestRecord{
			RequestID:     "hg_7f3a9c2e",
			AgentName:     "invoice-processor",
			ToolName:      "fs.write",
			SubjectDigest: digest,
			Timestamp:     time.Now().UTC().Truncate(time.Second),
		},
		Response:       &respRec,
		ApproverPubkey: approver.did,
	}

	got, err := RecordedDecisionFrom(roundTrip(t, rec.Details()))
	if err != nil {
		t.Fatalf("RecordedDecisionFrom() error: %v", err)
	}
	if got == nil {
		t.Fatal("RecordedDecisionFrom() = nil, want the recorded decision")
	}
	if got.Request != rec.Request {
		t.Errorf("request = %+v, want %+v", got.Request, rec.Request)
	}
	if got.ApproverPubkey != approver.did {
		t.Errorf("approver_pubkey = %q, want %q", got.ApproverPubkey, approver.did)
	}
	if got.Response == nil {
		t.Fatal("response = nil, want the recorded decision")
	}
	if got.Response.wire() != respRec.wire() || got.Response.Truncated != respRec.Truncated {
		t.Fatalf("response = %+v, want %+v", *got.Response, respRec)
	}
	if got.Response.DecidedAt == nil || !got.Response.DecidedAt.Equal(*respRec.DecidedAt) {
		t.Errorf("decided_at = %v, want %v", got.Response.DecidedAt, respRec.DecidedAt)
	}

	// The whole point of persisting it: the recovered record reproduces the
	// signed payload and verifies offline, with nothing but the log and the
	// approver's public key.
	approved, reason, err := VerifyDecision(
		got.ApproverPubkey, got.Request.RequestID, got.Request.SubjectDigest, got.Response.wire())
	if err != nil || !approved || reason != ReasonApproved {
		t.Fatalf("recovered decision did not re-verify: approved=%v reason=%s err=%v", approved, reason, err)
	}
}

// TestRecordedRequestOmitsArguments pins the §9 exclusion approved in Phase
// 0: the record names which call was gated via its digest and never copies
// the arguments, which routinely carry secrets.
func TestRecordedRequestOmitsArguments(t *testing.T) {
	rec := &RecordedDecision{Request: RequestRecord{
		RequestID:     "hg_1",
		ToolName:      "fs.write",
		SubjectDigest: "sha256:aa",
	}}
	b, err := json.Marshal(rec.Details())
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	for _, forbidden := range []string{"arguments", "tool_call"} {
		if strings.Contains(string(b), forbidden) {
			t.Errorf("recorded request contains %q: %s", forbidden, b)
		}
	}
}

func TestNewResponseRecordLeavesRealDecisionIntact(t *testing.T) {
	approver := newTestApprover(t)
	digest := "sha256:4b3f00000000000000000000000000000000000000000000000000000000e91a"
	resp := approver.sign("hg_7f3a9c2e", "approved", digest)

	rec := NewResponseRecord(resp)
	if rec.Truncated {
		t.Error("a genuine decision was marked truncated — the cap is too small for a real signature")
	}
	if rec.Signature != resp.Signature || rec.SubjectDigest != resp.SubjectDigest ||
		rec.RequestID != resp.RequestID || rec.Decision != resp.Decision {
		t.Errorf("record = %+v, want the response's own fields", rec)
	}
}

// TestNewResponseRecordClampsEveryField: a rejected decision is still
// recorded, and its contents are whatever an untrusted endpoint chose. Each
// field is bounded on its own — a cap on the response as a whole would let
// one field carry all of it into a signed, hash-chained log.
func TestNewResponseRecordClampsEveryField(t *testing.T) {
	huge := strings.Repeat("A", 40<<10)
	for _, tc := range []struct {
		name string
		resp DecisionResponse
	}{
		{"request_id", DecisionResponse{RequestID: huge}},
		{"decision", DecisionResponse{Decision: huge}},
		{"subject_digest", DecisionResponse{SubjectDigest: huge}},
		{"signature", DecisionResponse{Signature: huge}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := NewResponseRecord(tc.resp)
			if !rec.Truncated {
				t.Error("oversized field was not marked truncated")
			}
			b, err := json.Marshal(rec)
			if err != nil {
				t.Fatalf("json.Marshal() error: %v", err)
			}
			if len(b) > 4*EvidenceFieldMax {
				t.Errorf("record is %d bytes for a %d-byte field — not bounded", len(b), len(huge))
			}
		})
	}
}

// TestClampEvidenceDropsPartialRune: truncation must not leave a broken
// multi-byte character in a log line that is about to be signed.
func TestClampEvidenceDropsPartialRune(t *testing.T) {
	// 3-byte runes do not divide evenly into the cap, so the cut lands mid-rune.
	got, cut := clampEvidence(strings.Repeat("→", EvidenceFieldMax))
	if !cut {
		t.Fatal("clampEvidence() reported no truncation")
	}
	if !json.Valid([]byte(`"` + got + `"`)) {
		t.Error("clamped value is not valid UTF-8 for JSON")
	}
	for _, r := range got {
		if r == '�' {
			t.Error("clamped value contains a replacement rune — a partial rune survived")
		}
	}
}

func TestRecordedDecisionFromAbsentAndNil(t *testing.T) {
	// An entry with no evidence — a terminal-decided gate, or any entry
	// written before spec 0.4.0 — is not an error.
	got, err := RecordedDecisionFrom(map[string]any{"tool": "fs.write"})
	if err != nil || got != nil {
		t.Errorf("RecordedDecisionFrom(no evidence) = (%v, %v), want (nil, nil)", got, err)
	}

	// A nil RecordedDecision contributes no details at all, which is what
	// keeps a terminal gate's entry exactly as it has always been.
	var none *RecordedDecision
	if d := none.Details(); d != nil {
		t.Errorf("(*RecordedDecision)(nil).Details() = %v, want nil", d)
	}
}

func TestRecordedDecisionFromMalformed(t *testing.T) {
	details := map[string]any{DetailDecisionRequest: "not an object"}
	if _, err := RecordedDecisionFrom(details); err == nil {
		t.Error("RecordedDecisionFrom() accepted a malformed decision_request")
	}
}
