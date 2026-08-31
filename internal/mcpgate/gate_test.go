package mcpgate

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/pkg/did"
	"github.com/constle/constle/pkg/manifest"
)

// fixedApprover returns a fixed decision after an optional delay, or
// DecisionNone if ctx expires first — the same contract as a human answering
// (or not answering) the terminal prompt.
type fixedApprover struct {
	decision Decision
	delay    time.Duration
}

func (a *fixedApprover) Decide(ctx context.Context, req Request) Decision {
	if a.delay > 0 {
		select {
		case <-time.After(a.delay):
		case <-ctx.Done():
			return DecisionNone
		}
	}
	if ctx.Err() != nil {
		return DecisionNone
	}
	return a.decision
}

// gateHarness bundles a bound gate, its counting upstream, and the audit log.
type gateHarness struct {
	gate     *Gate
	upstream *httptest.Server
	calls    *atomic.Int64
	baseURL  string // http://127.0.0.1:port/<token>/servers/email
	logPath  string
	logger   *audit.Logger
}

// newHarness builds a gate for one server "email" with tools
// [send_email, list_inbox], gating send_email.
func newHarness(t *testing.T, approver Approver, onTimeout string) *gateHarness {
	t.Helper()

	calls := &atomic.Int64{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"sent"}]}}`)
	}))
	t.Cleanup(up.Close)

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New(logPath)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	m := &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "test-agent"},
		MCP: manifest.MCP{Servers: []manifest.MCPServer{
			{ID: "email", URL: up.URL, Tools: []string{"send_email", "list_inbox"}},
		}},
		HumanGates: manifest.HumanGates{
			Enabled:                true,
			RequireApprovalFor:     []string{"send_email"},
			ApprovalTimeoutSeconds: 300,
			OnTimeout:              onTimeout,
		},
	}

	g, err := New(m, approver, nil, logger, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	g.timeoutOverride = 200 * time.Millisecond

	port, token, err := g.Bind("testrun01", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })

	return &gateHarness{
		gate:     g,
		upstream: up,
		calls:    calls,
		baseURL:  fmt.Sprintf("http://127.0.0.1:%d/%s/servers/email", port, token),
		logPath:  logPath,
		logger:   logger,
	}
}

func toolCallBody(tool string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":{"to":"x@example.com"}}}`, tool)
}

func postJSON(t *testing.T, url, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

// auditEvents reads back the JSONL audit log written during a test.
func auditEvents(t *testing.T, h *gateHarness) []audit.Entry {
	t.Helper()
	data, err := os.ReadFile(h.logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var entries []audit.Entry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries
}

func eventsOfType(entries []audit.Entry, et audit.EventType) []audit.Entry {
	var out []audit.Entry
	for _, e := range entries {
		if e.Event == et {
			out = append(out, e)
		}
	}
	return out
}

func TestUngatedToolPassesThrough(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionDenied}, "abort")

	status, body := postJSON(t, h.baseURL, toolCallBody("list_inbox"))
	if status != 200 || !strings.Contains(body, "sent") {
		t.Fatalf("ungated call: status=%d body=%s", status, body)
	}
	if h.calls.Load() != 1 {
		t.Errorf("upstream calls = %d, want 1", h.calls.Load())
	}
	if got := eventsOfType(auditEvents(t, h), audit.EventGateTriggered); len(got) != 0 {
		t.Errorf("ungated call must not trigger a gate, got %d gate_triggered", len(got))
	}
}

func TestGatedToolApproved(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionApproved}, "abort")

	status, body := postJSON(t, h.baseURL, toolCallBody("send_email"))
	if status != 200 || !strings.Contains(body, "sent") {
		t.Fatalf("approved call: status=%d body=%s", status, body)
	}
	if h.calls.Load() != 1 {
		t.Errorf("upstream calls = %d, want 1", h.calls.Load())
	}

	entries := auditEvents(t, h)
	if len(eventsOfType(entries, audit.EventGateTriggered)) != 1 ||
		len(eventsOfType(entries, audit.EventGateApproved)) != 1 {
		t.Errorf("want 1 gate_triggered + 1 gate_approved, got %+v", entries)
	}
	if entries[0].RunID != "testrun01" {
		t.Errorf("run_id = %q, want testrun01", entries[0].RunID)
	}
}

func TestGatedToolDeniedFailsCallButNotRun(t *testing.T) {
	aborted := &atomic.Bool{}
	h := newHarness(t, &fixedApprover{decision: DecisionDenied}, "abort")
	h.gate.SetAbortRun(func() { aborted.Store(true) })

	status, body := postJSON(t, h.baseURL, toolCallBody("send_email"))
	if status != 200 || !strings.Contains(body, "DENIED") {
		t.Fatalf("denied call: status=%d body=%s", status, body)
	}
	if !strings.Contains(body, `"error"`) {
		t.Errorf("denied call must return a JSON-RPC error, got %s", body)
	}
	if h.calls.Load() != 0 {
		t.Errorf("denied call reached upstream: %d calls", h.calls.Load())
	}
	if aborted.Load() {
		t.Error("deny must not abort the run — only timeout+abort does")
	}

	entries := auditEvents(t, h)
	if len(eventsOfType(entries, audit.EventGateDenied)) != 1 {
		t.Errorf("want 1 gate_denied, got %+v", entries)
	}
}

func TestGateTimeoutAbort(t *testing.T) {
	aborted := &atomic.Bool{}
	// Approver never answers within the 200ms override.
	h := newHarness(t, &fixedApprover{decision: DecisionApproved, delay: time.Hour}, "abort")
	h.gate.SetAbortRun(func() { aborted.Store(true) })

	status, body := postJSON(t, h.baseURL, toolCallBody("send_email"))
	if status != 200 || !strings.Contains(body, "timed out") {
		t.Fatalf("timeout call: status=%d body=%s", status, body)
	}
	if h.calls.Load() != 0 {
		t.Errorf("timed-out call reached upstream: %d calls", h.calls.Load())
	}
	if !aborted.Load() {
		t.Error("on_timeout=abort must invoke the abort callback")
	}

	entries := auditEvents(t, h)
	if len(eventsOfType(entries, audit.EventGateTimeout)) != 1 {
		t.Errorf("want 1 gate_timeout, got %+v", entries)
	}
}

func TestGateTimeoutProceed(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionDenied, delay: time.Hour}, "proceed")

	status, body := postJSON(t, h.baseURL, toolCallBody("send_email"))
	if status != 200 || !strings.Contains(body, "sent") {
		t.Fatalf("proceed call: status=%d body=%s", status, body)
	}
	if h.calls.Load() != 1 {
		t.Errorf("on_timeout=proceed must forward, got %d upstream calls", h.calls.Load())
	}
	entries := auditEvents(t, h)
	if len(eventsOfType(entries, audit.EventGateTimeout)) != 1 {
		t.Errorf("want 1 gate_timeout, got %+v", entries)
	}
}

func TestUndeclaredToolBlocked(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionApproved}, "abort")

	status, body := postJSON(t, h.baseURL, toolCallBody("delete_everything"))
	if status != 200 || !strings.Contains(body, "not declared") {
		t.Fatalf("undeclared tool: status=%d body=%s", status, body)
	}
	if h.calls.Load() != 0 {
		t.Errorf("undeclared tool reached upstream: %d calls", h.calls.Load())
	}
	entries := auditEvents(t, h)
	if len(eventsOfType(entries, audit.EventMCPToolBlocked)) != 1 {
		t.Errorf("want 1 mcp_tool_blocked, got %+v", entries)
	}
}

func TestFailClosedInputs(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionApproved}, "abort")

	// JSON-RPC batch: could smuggle a gated call past an object parse.
	batch := `[` + toolCallBody("send_email") + `]`
	if status, _ := postJSON(t, h.baseURL, batch); status != http.StatusBadRequest {
		t.Errorf("batch request: status=%d, want 400", status)
	}

	// Garbage body.
	if status, _ := postJSON(t, h.baseURL, "not json"); status != http.StatusBadRequest {
		t.Errorf("garbage body: status=%d, want 400", status)
	}

	// Wrong token.
	badToken := strings.Replace(h.baseURL, h.gate.token, strings.Repeat("0", 32), 1)
	if status, _ := postJSON(t, badToken, toolCallBody("list_inbox")); status != http.StatusNotFound {
		t.Errorf("wrong token: status=%d, want 404", status)
	}

	// Undeclared server id.
	badServer := strings.Replace(h.baseURL, "/servers/email", "/servers/other", 1)
	if status, _ := postJSON(t, badServer, toolCallBody("list_inbox")); status != http.StatusForbidden {
		t.Errorf("undeclared server: status=%d, want 403", status)
	}

	// Compressed body the gate cannot inspect.
	req, _ := http.NewRequest("POST", h.baseURL, strings.NewReader("x"))
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gzip request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("gzip body: status=%d, want 415", resp.StatusCode)
	}

	if h.calls.Load() != 0 {
		t.Errorf("fail-closed inputs reached upstream: %d calls", h.calls.Load())
	}
}

// TestNonInteractiveStdinFallsThroughToTimeout proves that a backgrounded
// run (stdin not a tty) never blocks on a prompt read: the approver skips
// the prompt and the gate resolves by on_timeout.
func TestNonInteractiveStdinFallsThroughToTimeout(t *testing.T) {
	var out strings.Builder
	approver := &TerminalApprover{
		In:          strings.NewReader("a\n"), // would approve IF (wrongly) read
		Out:         &out,
		Interactive: false,
	}

	aborted := &atomic.Bool{}
	h := newHarness(t, approver, "abort")
	h.gate.SetAbortRun(func() { aborted.Store(true) })

	start := time.Now()
	status, body := postJSON(t, h.baseURL, toolCallBody("send_email"))
	elapsed := time.Since(start)

	if status != 200 || !strings.Contains(body, "timed out") {
		t.Fatalf("non-interactive gate: status=%d body=%s", status, body)
	}
	if h.calls.Load() != 0 {
		t.Errorf("non-interactive gate reached upstream: %d calls", h.calls.Load())
	}
	if !aborted.Load() {
		t.Error("non-interactive timeout with on_timeout=abort must abort")
	}
	if elapsed < 150*time.Millisecond {
		t.Errorf("gate resolved in %v — it must wait out the timeout, not read stdin", elapsed)
	}
	if !strings.Contains(out.String(), "stdin is not a terminal") {
		t.Errorf("missing non-interactive notice in output: %q", out.String())
	}
	if len(eventsOfType(auditEvents(t, h), audit.EventGateTimeout)) != 1 {
		t.Error("want exactly 1 gate_timeout event")
	}
}

// promptWatcher is a synchronized Out writer that signals each time the
// approve/deny prompt is printed, so tests can answer like a human would —
// only after actually seeing the prompt (type-ahead is deliberately dropped
// by the approver's stale-input drain).
type promptWatcher struct {
	mu      sync.Mutex
	buf     strings.Builder
	prompts chan struct{}
}

func newPromptWatcher() *promptWatcher {
	return &promptWatcher{prompts: make(chan struct{}, 16)}
}

func (p *promptWatcher) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if strings.Contains(string(b), "approve?") {
		p.prompts <- struct{}{}
	}
	return p.buf.Write(b)
}

// TestInteractiveApproveAndDeny exercises the terminal approver end to end
// through a pipe standing in for a tty, answering prompts as they appear
// (junk first, to exercise re-prompting).
func TestInteractiveApproveAndDeny(t *testing.T) {
	inR, inW := io.Pipe()
	out := newPromptWatcher()
	approver := &TerminalApprover{In: inR, Out: out, Interactive: true}

	h := newHarness(t, approver, "abort")
	h.gate.timeoutOverride = 5 * time.Second

	answers := []string{"what\na\n", "d\n"} // first prompt: junk then approve
	go func() {
		w := bufio.NewWriter(inW)
		for _, answer := range answers {
			<-out.prompts
			_, _ = fmt.Fprint(w, answer)
			_ = w.Flush()
		}
	}()

	if status, body := postJSON(t, h.baseURL, toolCallBody("send_email")); status != 200 || !strings.Contains(body, "sent") {
		t.Fatalf("approved: status=%d body=%s", status, body)
	}
	if status, body := postJSON(t, h.baseURL, toolCallBody("send_email")); !strings.Contains(body, "DENIED") {
		t.Fatalf("denied: status=%d body=%s", status, body)
	}
	if h.calls.Load() != 1 {
		t.Errorf("upstream calls = %d, want 1 (approved only)", h.calls.Load())
	}
}

// TestApproveVersusTimeoutRace fires approvals right at the timeout boundary
// and checks the invariant that must hold no matter which side wins: the
// upstream is called if and only if gate_approved was logged, and every gate
// resolves with exactly one terminal audit event.
func TestApproveVersusTimeoutRace(t *testing.T) {
	const rounds = 12

	for i := 0; i < rounds; i++ {
		h := newHarness(t, &fixedApprover{
			decision: DecisionApproved,
			delay:    200 * time.Millisecond, // == timeoutOverride: a true race
		}, "abort")
		h.gate.SetAbortRun(func() {})

		postJSON(t, h.baseURL, toolCallBody("send_email"))

		entries := auditEvents(t, h)
		approved := len(eventsOfType(entries, audit.EventGateApproved))
		timedOut := len(eventsOfType(entries, audit.EventGateTimeout))
		denied := len(eventsOfType(entries, audit.EventGateDenied))

		if approved+timedOut+denied != 1 {
			t.Fatalf("round %d: want exactly one terminal gate event, got approved=%d timeout=%d denied=%d",
				i, approved, timedOut, denied)
		}
		upstreamCalled := h.calls.Load() > 0
		if upstreamCalled != (approved == 1) {
			t.Fatalf("round %d: upstream called=%v but approved=%d — enforcement and audit disagree",
				i, upstreamCalled, approved)
		}
		_ = h.gate.Close()
	}
}

// TestGateKilledMidFlightFailsClosed is the unit-level half of the Phase 3
// adversarial check: the gate dies while a gated call is blocked waiting for
// approval. The agent's call must fail with a transport error — it must
// never fall through to the real MCP server.
func TestGateKilledMidFlightFailsClosed(t *testing.T) {
	// An approver that never answers, so the call is parked in the gate.
	h := newHarness(t, &fixedApprover{decision: DecisionApproved, delay: time.Hour}, "abort")
	h.gate.timeoutOverride = time.Hour

	var wg sync.WaitGroup
	wg.Add(1)
	var postErr error
	go func() {
		defer wg.Done()
		resp, err := http.Post(h.baseURL, "application/json", strings.NewReader(toolCallBody("send_email")))
		if err == nil {
			_ = resp.Body.Close()
			// A response is only acceptable if it is a gate-side error,
			// never a success that implies the upstream answered.
			if resp.StatusCode == 200 && h.calls.Load() > 0 {
				postErr = fmt.Errorf("call passed through to upstream after gate death")
			}
			return
		}
		postErr = nil // transport error: the fail-closed outcome we want
	}()

	// Let the call reach the gate and park in the approval wait.
	time.Sleep(150 * time.Millisecond)
	if err := h.gate.Close(); err != nil {
		t.Fatalf("gate.Close: %v", err)
	}
	wg.Wait()

	if postErr != nil {
		t.Fatal(postErr)
	}
	if h.calls.Load() != 0 {
		t.Fatalf("upstream was called %d times — gated call leaked past a dead gate", h.calls.Load())
	}

	// And with the gate gone, the agent cannot reconnect at all.
	if _, err := http.Post(h.baseURL, "application/json", strings.NewReader(toolCallBody("list_inbox"))); err == nil {
		t.Fatal("connection to a closed gate succeeded — expected connection refused")
	}
}

// testSigner is an in-memory audit.Signer backed by a throwaway Ed25519 key.
type testSigner struct {
	did  string
	priv ed25519.PrivateKey
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	d, err := did.FromPublicKey(pub)
	if err != nil {
		t.Fatalf("did from key: %v", err)
	}
	return &testSigner{did: d, priv: priv}
}

func (s *testSigner) DID() string            { return s.did }
func (s *testSigner) Sign(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }

// TestToolCallEventsPreserveSignedChain: a signed log interleaving the new
// tool_call_start/end events with gate events must still verify end to end —
// the chain and signatures are agnostic to event types, and this pins that.
func TestToolCallEventsPreserveSignedChain(t *testing.T) {
	signer := newTestSigner(t)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"sent"}]}}`)
	}))
	t.Cleanup(up.Close)

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.NewSigned(logPath, signer)
	if err != nil {
		t.Fatalf("audit.NewSigned: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	m := &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "test-agent"},
		MCP: manifest.MCP{Servers: []manifest.MCPServer{
			{ID: "email", URL: up.URL, Tools: []string{"send_email", "list_inbox"}},
		}},
		HumanGates: manifest.HumanGates{
			Enabled:                true,
			RequireApprovalFor:     []string{"send_email"},
			ApprovalTimeoutSeconds: 300,
			OnTimeout:              "abort",
		},
	}
	g, err := New(m, &fixedApprover{decision: DecisionApproved}, nil, logger, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	port, token, err := g.Bind("signedrun01", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	baseURL := fmt.Sprintf("http://127.0.0.1:%d/%s/servers/email", port, token)

	postJSON(t, baseURL, toolCallBody("list_inbox"))        // start + end
	postJSON(t, baseURL, toolCallBody("send_email"))        // gate + start + end
	postJSON(t, baseURL, toolCallBody("delete_everything")) // blocked

	if err := logger.Err(); err != nil {
		t.Fatalf("audit writes failed: %v", err)
	}
	// 2 + (2 gate + 2 tool_call) + 1 blocked = 7 entries, all chained. The
	// last write can land moments after the final response is read.
	waitFor(t, func() bool {
		data, err := os.ReadFile(logPath)
		return err == nil && len(strings.Split(strings.TrimSpace(string(data)), "\n")) == 7
	})
	report, err := audit.VerifyFile(logPath, signer.did)
	if err != nil {
		t.Fatalf("signed log with tool_call events failed verification: %v", err)
	}
	if report.Entries != 7 {
		t.Errorf("verified entries = %d, want 7", report.Entries)
	}
}

// waitFor polls cond until it holds or the deadline passes. The audit write
// for tool_call_end lands moments after the proxied response reaches the
// client — the handler goroutine is still finishing — so tests that assert on
// it must wait for the log, not assume the response implies the write.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not reached within deadline")
	}
}

// eventIndex returns the position of the first entry of the given type, or -1.
func eventIndex(entries []audit.Entry, et audit.EventType) int {
	for i, e := range entries {
		if e.Event == et {
			return i
		}
	}
	return -1
}

// TestForwardedToolCallEmitsStartAndEnd: an ungated tools/call that reaches
// the upstream must bracket itself with tool_call_start / tool_call_end,
// carrying the identifiers needed to read the log mid-run.
func TestForwardedToolCallEmitsStartAndEnd(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionDenied}, "abort")

	if status, body := postJSON(t, h.baseURL, toolCallBody("list_inbox")); status != 200 || !strings.Contains(body, "sent") {
		t.Fatalf("ungated call: status=%d body=%s", status, body)
	}

	waitFor(t, func() bool {
		return len(eventsOfType(auditEvents(t, h), audit.EventToolCallEnd)) == 1
	})
	entries := auditEvents(t, h)
	starts := eventsOfType(entries, audit.EventToolCallStart)
	ends := eventsOfType(entries, audit.EventToolCallEnd)
	if len(starts) != 1 || len(ends) != 1 {
		t.Fatalf("want 1 tool_call_start + 1 tool_call_end, got %d + %d", len(starts), len(ends))
	}
	if eventIndex(entries, audit.EventToolCallStart) > eventIndex(entries, audit.EventToolCallEnd) {
		t.Error("tool_call_start must precede tool_call_end")
	}

	start := starts[0]
	if start.RunID != "testrun01" || start.AgentName != "test-agent" {
		t.Errorf("start attribution: run_id=%q agent=%q", start.RunID, start.AgentName)
	}
	if start.Details["server"] != "email" || start.Details["tool"] != "list_inbox" {
		t.Errorf("start details = %+v", start.Details)
	}
	if ab, ok := start.Details["args_bytes"].(float64); !ok || ab <= 0 {
		t.Errorf("args_bytes = %v, want > 0 (size recorded, content not)", start.Details["args_bytes"])
	}
	if _, hasArgs := start.Details["arguments"]; hasArgs {
		t.Error("tool arguments must not be copied into the audit log")
	}
	if start.Details["rpc_id"] != "1" {
		t.Errorf("rpc_id = %v, want \"1\"", start.Details["rpc_id"])
	}

	end := ends[0]
	if end.Details["server"] != "email" || end.Details["tool"] != "list_inbox" || end.Details["rpc_id"] != "1" {
		t.Errorf("end details = %+v", end.Details)
	}
	if st, ok := end.Details["http_status"].(float64); !ok || int(st) != 200 {
		t.Errorf("http_status = %v, want 200", end.Details["http_status"])
	}
	if _, ok := end.Details["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms missing from end details: %+v", end.Details)
	}
}

// TestGatedApprovedToolCallEventOrder: an approved gated call must read as a
// narrative — gate_triggered, gate_approved, tool_call_start, tool_call_end.
func TestGatedApprovedToolCallEventOrder(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionApproved}, "abort")

	if status, body := postJSON(t, h.baseURL, toolCallBody("send_email")); status != 200 || !strings.Contains(body, "sent") {
		t.Fatalf("approved call: status=%d body=%s", status, body)
	}

	waitFor(t, func() bool {
		return len(eventsOfType(auditEvents(t, h), audit.EventToolCallEnd)) == 1
	})
	entries := auditEvents(t, h)
	order := []audit.EventType{
		audit.EventGateTriggered,
		audit.EventGateApproved,
		audit.EventToolCallStart,
		audit.EventToolCallEnd,
	}
	prev := -1
	for _, et := range order {
		i := eventIndex(entries, et)
		if i < 0 {
			t.Fatalf("missing %s in %+v", et, entries)
		}
		if i < prev {
			t.Fatalf("%s out of order (index %d after %d) in %+v", et, i, prev, entries)
		}
		prev = i
	}
}

// TestUnforwardedCallsEmitNoToolCallEvents: a call that never reaches the
// upstream — undeclared tool, gate denied, or a non-tools/call method — must
// not claim it did.
func TestUnforwardedCallsEmitNoToolCallEvents(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionDenied}, "abort")

	postJSON(t, h.baseURL, toolCallBody("delete_everything")) // undeclared → blocked
	postJSON(t, h.baseURL, toolCallBody("send_email"))        // gated → denied
	postJSON(t, h.baseURL, `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)

	entries := auditEvents(t, h)
	if n := len(eventsOfType(entries, audit.EventToolCallStart)); n != 0 {
		t.Errorf("got %d tool_call_start events for calls that never reached the upstream", n)
	}
	if n := len(eventsOfType(entries, audit.EventToolCallEnd)); n != 0 {
		t.Errorf("got %d tool_call_end events for calls that never reached the upstream", n)
	}
	if h.calls.Load() != 1 { // only tools/list passes through
		t.Errorf("upstream calls = %d, want 1 (tools/list only)", h.calls.Load())
	}
}

// TestStaleKeystrokeDoesNotApproveNextGate: input typed while no prompt is
// waiting must not resolve a later gate.
func TestStaleKeystrokeDoesNotApproveNextGate(t *testing.T) {
	inR, inW := io.Pipe()
	var out strings.Builder
	approver := &TerminalApprover{In: inR, Out: &out, Interactive: true}
	approver.readOnce.Do(approver.startReader)

	// Type "a" with no prompt waiting; give the reader a moment to park it.
	go func() { _, _ = fmt.Fprintln(inW, "a") }()
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	decision := approver.Decide(ctx, Request{Tool: "send_email", TimeoutSeconds: 1, OnTimeout: "abort"})
	if decision != DecisionNone {
		t.Fatalf("stale keystroke resolved the gate: decision=%v, want DecisionNone (timeout)", decision)
	}
}
