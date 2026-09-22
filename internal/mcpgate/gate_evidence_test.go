package mcpgate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/homedir"
	"github.com/constle/constle/internal/humangate"
	"github.com/constle/constle/pkg/manifest"
)

// evidenceHarness is a gate whose audit log is signed and whose gated calls
// are decided by a real WebhookApprover talking to a real decision endpoint
// over HTTP. Nothing here is stubbed between the decision and the log entry,
// which is what makes the assertions below evidence rather than a
// restatement of the code.
type evidenceHarness struct {
	gate     *Gate
	endpoint *fakeDecisionEndpoint
	approver testApprover
	signer   *testSigner
	baseURL  string
	logPath  string
	logger   *audit.Logger
}

func newEvidenceHarness(t *testing.T, onTimeout string) *evidenceHarness {
	t.Helper()
	approver := newTestApprover(t)
	endpoint := newFakeDecisionEndpoint(t)
	signer := newTestSigner(t)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"sent"}]}}`)
	}))
	t.Cleanup(up.Close)

	logLoc := homedir.Under(t.TempDir(), "audit.jsonl")
	logger, err := audit.NewSigned(logLoc, signer)
	if err != nil {
		t.Fatalf("audit.NewSigned: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	m := &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "test-agent"},
		MCP: manifest.MCP{Servers: []manifest.MCPServer{
			{ID: "email", URL: up.URL, Tools: []string{"send_email"}},
		}},
		HumanGates: manifest.HumanGates{
			Enabled:                true,
			RequireApprovalFor:     []string{"send_email"},
			ApprovalTimeoutSeconds: 300,
			OnTimeout:              onTimeout,
			ApproverPubkey:         approver.did,
		},
	}

	wa := &WebhookApprover{
		URL: endpoint.url(), ApproverPubkey: approver.did,
		PollInterval: 10 * time.Millisecond,
	}
	g, err := New(m, wa, nil, logger, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	g.timeoutOverride = 400 * time.Millisecond

	port, token, err := g.Bind("evidencerun", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })

	return &evidenceHarness{
		gate: g, endpoint: endpoint, approver: approver, signer: signer,
		baseURL: fmt.Sprintf("http://127.0.0.1:%d/%s/servers/email", port, token),
		logPath: logLoc.String(), logger: logger,
	}
}

// entriesFor reads the signed log, verifies it end to end, and returns the
// entries carrying the named event.
func (h *evidenceHarness) entriesFor(t *testing.T, event audit.EventType) ([]audit.Entry, *audit.VerifyReport) {
	t.Helper()
	waitFor(t, func() bool {
		data, err := os.ReadFile(h.logPath)
		return err == nil && strings.Contains(string(data), string(event))
	})
	report, err := audit.VerifyFile(h.logPath, h.signer.did)
	if err != nil {
		t.Fatalf("signed log failed verification: %v", err)
	}
	var out []audit.Entry
	for _, e := range report.Parsed {
		if e.Event == event {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no %s entry in the log", event)
	}
	return out, report
}

// signWith makes the endpoint answer every gate with a decision signed by a,
// carrying the given decision value.
func (h *evidenceHarness) signWith(a testApprover, decision string) {
	h.endpoint.mu.Lock()
	defer h.endpoint.mu.Unlock()
	h.endpoint.decide = func(req gateRequestWire) (humangate.DecisionResponse, bool) {
		return humangate.DecisionResponse{
			RequestID: req.RequestID, Decision: decision, SubjectDigest: req.SubjectDigest,
			Signature: a.sign(req.RequestID, decision, req.SubjectDigest),
			DecidedAt: time.Now().UTC(),
		}, true
	}
}

// TestWebhookApprovalIsProvableOffline is HG02 closed end to end: a gated
// call really approved over the webhook leaves a signed log that a third
// party can re-verify holding nothing but the log and the Agentfile's
// approver_pubkey. Before this, gate_approved recorded that something was
// approved and nothing that showed the approver had approved it.
func TestWebhookApprovalIsProvableOffline(t *testing.T) {
	h := newEvidenceHarness(t, "abort")
	h.signWith(h.approver, "approved")

	if status, _ := postJSON(t, h.baseURL, toolCallBody("send_email")); status != http.StatusOK {
		t.Fatalf("gated call status = %d, want 200", status)
	}

	approvals, report := h.entriesFor(t, audit.EventGateApproved)
	e := approvals[0]

	rec, err := humangate.RecordedDecisionFrom(e.Details)
	if err != nil {
		t.Fatalf("RecordedDecisionFrom() error: %v", err)
	}
	if rec == nil || rec.Response == nil {
		t.Fatal("gate_approved carries no signed decision — HG02 is still open")
	}
	if rec.Request.RequestID == "" || !strings.HasPrefix(rec.Request.RequestID, "hg_") {
		t.Errorf("recorded request_id = %q, want the id the gate minted", rec.Request.RequestID)
	}
	if rec.ApproverPubkey != h.approver.did {
		t.Errorf("recorded approver_pubkey = %q, want %q", rec.ApproverPubkey, h.approver.did)
	}
	if rec.Request.ToolName != "send_email" {
		t.Errorf("recorded tool = %q, want send_email", rec.Request.ToolName)
	}

	// The arguments of the gated call must not have travelled into the log.
	line, err := json.Marshal(e.Details)
	if err != nil {
		t.Fatalf("json.Marshal(details): %v", err)
	}
	if strings.Contains(string(line), "x@example.com") {
		t.Errorf("the gated call's arguments leaked into the audit log: %s", line)
	}

	// And the whole point: it re-verifies against the pinned approver key.
	decisions, err := humangate.VerifyDecisions(report.Parsed, h.approver.did)
	if err != nil {
		t.Fatalf("VerifyDecisions() error: %v", err)
	}
	if !decisions.OK() {
		t.Fatalf("recorded decision did not re-verify: %v", decisions.Failures)
	}
	if decisions.Verified != 1 {
		t.Errorf("Verified = %d, want 1", decisions.Verified)
	}
}

// TestWebhookRejectionRecordsTheDecisionItRejected: the fail-closed events
// are exactly where an investigator needs to see what actually arrived, so
// the rejected decision is recorded too — and re-verifies as that same
// rejection rather than as a fresh accusation.
func TestWebhookRejectionRecordsTheDecisionItRejected(t *testing.T) {
	h := newEvidenceHarness(t, "abort")
	impostor := newTestApprover(t)
	h.signWith(impostor, "approved") // genuine signature, wrong key

	// A gate denial is a JSON-RPC error inside a 200, not an HTTP status.
	if _, body := postJSON(t, h.baseURL, toolCallBody("send_email")); !strings.Contains(body, "DENIED") {
		t.Fatalf("a decision signed by the wrong key was not denied: %s", body)
	}

	entries, report := h.entriesFor(t, audit.EventGateSignatureInvalid)
	rec, err := humangate.RecordedDecisionFrom(entries[0].Details)
	if err != nil || rec == nil || rec.Response == nil {
		t.Fatalf("gate_signature_invalid recorded no decision (rec=%v err=%v)", rec, err)
	}
	if rec.Response.Signature == "" {
		t.Error("the rejected decision's signature was not recorded")
	}

	decisions, err := humangate.VerifyDecisions(report.Parsed, h.approver.did)
	if err != nil {
		t.Fatalf("VerifyDecisions() error: %v", err)
	}
	if !decisions.OK() {
		t.Errorf("a recorded rejection did not reproduce offline: %v", decisions.Failures)
	}
}

// TestUnansweredGateRecordsItsRequestID: a gate nobody answers has no signed
// decision to keep, but the request_id it minted is the only handle that
// correlates it with the receiver's own records — and it used to die inside
// the approver.
func TestUnansweredGateRecordsItsRequestID(t *testing.T) {
	h := newEvidenceHarness(t, "proceed") // proceed: no run abort to fight in a unit test
	// endpoint.decide stays nil — every poll answers 202, nothing is decided.

	postJSON(t, h.baseURL, toolCallBody("send_email"))

	entries, report := h.entriesFor(t, audit.EventGateTimeout)
	rec, err := humangate.RecordedDecisionFrom(entries[0].Details)
	if err != nil {
		t.Fatalf("RecordedDecisionFrom() error: %v", err)
	}
	if rec == nil {
		t.Fatal("gate_timeout records no request — the gate cannot be correlated with the endpoint")
	}
	if !strings.HasPrefix(rec.Request.RequestID, "hg_") {
		t.Errorf("recorded request_id = %q, want the id the gate opened", rec.Request.RequestID)
	}
	if rec.Response != nil {
		t.Error("gate_timeout recorded a decision, but nothing was decided")
	}

	decisions, err := humangate.VerifyDecisions(report.Parsed, h.approver.did)
	if err != nil {
		t.Fatalf("VerifyDecisions() error: %v", err)
	}
	if !decisions.OK() || decisions.Unanswered != 1 {
		t.Errorf("unanswered gate = %+v, want one Unanswered and no failures", decisions)
	}
}

// TestTerminalGateRecordsNoEvidence: a decision made at the keyboard
// produces no signed statement, so the entry must stay exactly as it was.
// The evidence machinery is additive to the webhook path, not a new
// requirement on every gate.
func TestTerminalGateRecordsNoEvidence(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionApproved}, "abort")

	postJSON(t, h.baseURL, toolCallBody("send_email"))
	waitFor(t, func() bool {
		data, err := os.ReadFile(h.logPath)
		return err == nil && strings.Contains(string(data), string(audit.EventGateApproved))
	})

	data, err := os.ReadFile(h.logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	for _, key := range []string{
		humangate.DetailDecisionRequest,
		humangate.DetailDecisionResponse,
		humangate.DetailApproverPubkey,
	} {
		if strings.Contains(string(data), key) {
			t.Errorf("a terminal-decided gate wrote %q into the audit log", key)
		}
	}
}

// TestRaceApproverCarriesEvidenceOutOfAnUndecidedRace: with the terminal and
// the webhook racing, a timeout leaves every source returning DecisionNone.
// The webhook's request record has to survive that drain, or gate_timeout
// loses the request_id again on exactly the configuration the CLI builds.
func TestRaceApproverCarriesEvidenceOutOfAnUndecidedRace(t *testing.T) {
	want := &humangate.RecordedDecision{Request: humangate.RequestRecord{RequestID: "hg_abc"}}
	race := RaceApprover{Approvers: []Approver{
		&fixedApprover{decision: DecisionNone},
		evidenceOnlyApprover{evidence: want},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	out := race.DecideWithReason(ctx, newTestRequest("send_email", `{}`))
	if out.Decision != DecisionNone {
		t.Fatalf("Decision = %v, want DecisionNone", out.Decision)
	}
	if out.Evidence == nil || out.Evidence.Request.RequestID != "hg_abc" {
		t.Errorf("Evidence = %+v, want the undecided source's request record", out.Evidence)
	}
}

// evidenceOnlyApprover returns no decision but does return evidence, like a
// webhook approver whose gate timed out unanswered.
type evidenceOnlyApprover struct{ evidence *humangate.RecordedDecision }

func (a evidenceOnlyApprover) Decide(ctx context.Context, req Request) Decision {
	return a.DecideWithReason(ctx, req).Decision
}

func (a evidenceOnlyApprover) DecideWithReason(context.Context, Request) Outcome {
	return Outcome{Decision: DecisionNone, Evidence: a.evidence}
}

// TestEmptyToolNameIsRefused closes the producer side of the review finding
// that an empty tool name reaches the audit record.
//
// The offline verifier requires an entry's tool name and its recorded
// request's to be present and equal, and treats an empty one as absent —
// which is what stops a deleted field passing for a missing one. A gate that
// could arm on "" would therefore write correctly signed records that can
// never be verified. The manifest refuses to declare the empty entry and the
// gate refuses to route the empty call, so neither half is reachable.
//
// Tested at parseJSONRPC rather than through the gate: a call whose tool
// name is empty is also rejected by the server's tool allowlist, so an
// end-to-end assertion passes whether or not this check exists. Isolating it
// here is what makes the test evidence rather than decoration.
func TestEmptyToolNameIsRefused(t *testing.T) {
	_, err := parseJSONRPC([]byte(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"","arguments":{}}}`))
	if err == nil {
		t.Fatal("parseJSONRPC accepted a tools/call with an empty tool name")
	}
	if !errors.Is(err, errAmbiguousBody) {
		t.Errorf("error = %v, want it to join the ambiguous-body refusals", err)
	}

	// A named call on the same shape still parses, or the check is too broad.
	if _, err := parseJSONRPC([]byte(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{}}}`)); err != nil {
		t.Errorf("parseJSONRPC rejected a named tools/call: %v", err)
	}

	// A method that is not tools/call carries no tool name and must be
	// unaffected — the check belongs to the routed call, not to every body.
	if _, err := parseJSONRPC([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)); err != nil {
		t.Errorf("parseJSONRPC rejected a non-tools/call body: %v", err)
	}
}
