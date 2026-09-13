package mcpgate

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/homedir"
	"github.com/constle/constle/internal/humangate"
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
	bodies   *upstreamBodies
	baseURL  string // http://127.0.0.1:port/<token>/servers/email
	logPath  string
	logger   *audit.Logger
}

// upstreamBodies records the raw request bodies the fake MCP server actually
// received — what the gate chose to execute, as opposed to what the operator
// was shown. Keeping the two separately observable is what lets a test assert
// they agree.
type upstreamBodies struct {
	mu  sync.Mutex
	all []string
}

func (b *upstreamBodies) record(r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.all = append(b.all, string(data))
}

func (b *upstreamBodies) last() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.all) == 0 {
		return ""
	}
	return b.all[len(b.all)-1]
}

// newHarness builds a gate for one server "email" with tools
// [send_email, list_inbox], gating send_email.
func newHarness(t *testing.T, approver Approver, onTimeout string) *gateHarness {
	t.Helper()

	calls := &atomic.Int64{}
	bodies := &upstreamBodies{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		bodies.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"sent"}]}}`)
	}))
	t.Cleanup(up.Close)

	logLoc := homedir.Under(t.TempDir(), "audit.jsonl")
	logPath := logLoc.String()
	logger, err := audit.New(logLoc)
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
		bodies:   bodies,
		baseURL:  fmt.Sprintf("http://127.0.0.1:%d/%s/servers/email", port, token),
		logPath:  logPath,
		logger:   logger,
	}
}

func toolCallBody(tool string) string {
	return toolCallBodyWithArgs(tool, `{"to":"x@example.com"}`)
}

func toolCallBodyWithArgs(tool, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, tool, args)
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

// TestReasoningApproverOverridesEventAndAttribution pins runGate's
// integration with ReasoningApprover: a denial carrying a specific Event
// (e.g. a signature that failed to verify) must replace, not add to, the
// generic gate_denied line — exactly one terminal audit event per gate,
// same invariant as every other outcome — and decided_by must reflect the
// approver that actually decided.
func TestReasoningApproverOverridesEventAndAttribution(t *testing.T) {
	h := newHarness(t, &reasonedApprover{
		fixedApprover: fixedApprover{decision: DecisionDenied},
		decidedBy:     "webhook",
		event:         audit.EventGateSignatureInvalid,
	}, "abort")

	status, body := postJSON(t, h.baseURL, toolCallBody("send_email"))
	if status != 200 || !strings.Contains(body, "DENIED") {
		t.Fatalf("denied call: status=%d body=%s", status, body)
	}

	entries := auditEvents(t, h)
	if len(eventsOfType(entries, audit.EventGateSignatureInvalid)) != 1 {
		t.Errorf("want 1 gate_signature_invalid, got %+v", entries)
	}
	if len(eventsOfType(entries, audit.EventGateDenied)) != 0 {
		t.Errorf("gate_signature_invalid must replace gate_denied, not add to it; got %+v", entries)
	}

	resolved := eventsOfType(entries, audit.EventGateSignatureInvalid)[0]
	if got := resolved.Details["decided_by"]; got != "webhook" {
		t.Errorf("decided_by = %v, want %q", got, "webhook")
	}
}

// TestPlainApproverStillGetsGenericDenyEvent guards the fallback path: an
// Approver that is not also a ReasoningApprover (e.g. TerminalApprover)
// must keep logging the ordinary gate_denied event with decided_by:
// "terminal", unchanged from before ReasoningApprover existed.
func TestPlainApproverStillGetsGenericDenyEvent(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionDenied}, "abort")

	_, _ = postJSON(t, h.baseURL, toolCallBody("send_email"))

	entries := auditEvents(t, h)
	denied := eventsOfType(entries, audit.EventGateDenied)
	if len(denied) != 1 {
		t.Fatalf("want 1 gate_denied, got %+v", entries)
	}
	if got := denied[0].Details["decided_by"]; got != "terminal" {
		t.Errorf("decided_by = %v, want %q", got, "terminal")
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
	mu    sync.Mutex
	buf   strings.Builder
	match string // the prompt text to signal on
	// prompts is buffered so Write never blocks holding mu: a send that
	// parked here would deadlock the approver inside outf, turning a test
	// failure into a hung package.
	prompts chan struct{}
}

func newPromptWatcher() *promptWatcher {
	return &promptWatcher{match: "approve?", prompts: make(chan struct{}, 64)}
}

func (p *promptWatcher) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if strings.Contains(string(b), p.match) {
		select {
		case p.prompts <- struct{}{}:
		default:
		}
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

	logLoc := homedir.Under(t.TempDir(), "audit.jsonl")
	logPath := logLoc.String()
	logger, err := audit.NewSigned(logLoc, signer)
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

// doRequest issues one request with an arbitrary method and body, and returns
// the status, body, and response headers. Unlike postJSON it never assumes the
// method carries a JSON-RPC payload.
func doRequest(t *testing.T, method, url, body string) (int, string, http.Header) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("%s %s: build: %v", method, url, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data), resp.Header
}

// TestGatedToolUnreachableByAnyMethod is the regression test for the
// method-shaped bypass: servePOST inspected only POST, so every other method
// was reverse-proxied straight through. The upstream in newHarness routes on
// path alone and answers whatever arrives — the shape of a hand-rolled MCP
// server, and of net/http's own ServeMux, whose patterns match every method —
// so on the previous code each request below executed the gated tool while the
// approver was never consulted and the audit log stayed empty.
//
// The gated tool must now be unreachable by every method, including the
// lowercase spelling of POST that net/http accepts as a distinct method.
func TestGatedToolUnreachableByAnyMethod(t *testing.T) {
	for _, method := range []string{"GET", "DELETE", "PUT", "PATCH", "HEAD", "OPTIONS", "post", "FROBNICATE"} {
		t.Run(method, func(t *testing.T) {
			// Approver would APPROVE, so a gate that ran at all would still
			// forward: reaching the upstream here can only mean no gate ran.
			h := newHarness(t, &fixedApprover{decision: DecisionApproved}, "abort")

			status, _, _ := doRequest(t, method, h.baseURL, toolCallBody("send_email"))
			if status == http.StatusOK {
				t.Errorf("%s carrying a gated tools/call got 200 — it reached the upstream", method)
			}
			if h.calls.Load() != 0 {
				t.Errorf("%s carrying a gated tools/call reached the upstream %d time(s)", method, h.calls.Load())
			}

			entries := auditEvents(t, h)
			if n := len(eventsOfType(entries, audit.EventToolCallStart)); n != 0 {
				t.Errorf("%s: %d tool_call_start events for a call that never ran", method, n)
			}
			if n := len(eventsOfType(entries, audit.EventGateApproved)); n != 0 {
				t.Errorf("%s: %d gate_approved events — a refused request must not consume a decision", method, n)
			}
			if n := len(eventsOfType(entries, audit.EventMCPRequestBlocked)); n != 1 {
				t.Errorf("%s: want 1 mcp_request_blocked, got %+v", method, entries)
			}
		})
	}
}

// TestUndeclaredToolUnreachableByAnyMethod: the Agentfile's tools allowlist
// was bypassable the same way the human gate was — a tool the manifest never
// declared reached the upstream as long as the request was not a POST.
func TestUndeclaredToolUnreachableByAnyMethod(t *testing.T) {
	for _, method := range []string{"GET", "DELETE", "PUT", "FROBNICATE"} {
		t.Run(method, func(t *testing.T) {
			h := newHarness(t, &fixedApprover{decision: DecisionApproved}, "abort")

			doRequest(t, method, h.baseURL, toolCallBody("delete_everything"))
			if h.calls.Load() != 0 {
				t.Errorf("%s carrying an undeclared tools/call reached the upstream %d time(s)",
					method, h.calls.Load())
			}
		})
	}
}

// TestMethodsOutsideTheTransportAreRefused: Streamable HTTP defines POST, GET
// and DELETE on the MCP endpoint and nothing else, so anything else is refused
// with 405 and the Allow header RFC 9110 §15.5.6 requires — never forwarded,
// with or without a body.
func TestMethodsOutsideTheTransportAreRefused(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionApproved}, "abort")

	for _, method := range []string{"PUT", "PATCH", "HEAD", "OPTIONS", "TRACE", "post", "get", "FROBNICATE"} {
		status, _, header := doRequest(t, method, h.baseURL, "")
		if status != http.StatusMethodNotAllowed {
			t.Errorf("%s: status=%d, want 405", method, status)
		}
		if got := header.Get("Allow"); got != "GET, POST, DELETE" {
			t.Errorf("%s: Allow=%q, want %q", method, got, "GET, POST, DELETE")
		}
	}
	if h.calls.Load() != 0 {
		t.Errorf("a method outside the transport reached the upstream: %d calls", h.calls.Load())
	}
}

// TestBodilessGETAndDELETEStillReachTheUpstream guards the other direction of
// the fix. GET opens the server→client SSE stream and DELETE terminates the
// session; both are ordinary MCP traffic that carries no JSON-RPC message, and
// routing them through the POST path's parser would reject every one of them
// as an "empty JSON-RPC body" and break the transport outright.
func TestBodilessGETAndDELETEStillReachTheUpstream(t *testing.T) {
	for _, method := range []string{"GET", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			h := newHarness(t, &fixedApprover{decision: DecisionDenied}, "abort")

			status, body, _ := doRequest(t, method, h.baseURL, "")
			if status != http.StatusOK {
				t.Fatalf("bodiless %s: status=%d body=%s, want 200", method, status, body)
			}
			if h.calls.Load() != 1 {
				t.Fatalf("bodiless %s: upstream calls = %d, want 1", method, h.calls.Load())
			}

			entries := auditEvents(t, h)
			if n := len(eventsOfType(entries, audit.EventMCPRequestBlocked)); n != 0 {
				t.Errorf("bodiless %s must not be recorded as blocked, got %d", method, n)
			}
			if n := len(eventsOfType(entries, audit.EventToolCallStart)); n != 0 {
				t.Errorf("bodiless %s is not a tool call and must not be bracketed as one, got %d", method, n)
			}
		})
	}
}

// TestBodilessGETIsForwardedWithNoBodyFraming pins the wire shape of the
// forwarded stream-open. The gate reads the body to prove it is empty, so it
// must hand the proxy an explicitly empty one: a consumed reader left in place
// with a chunked framing would reach the upstream as a lone terminating chunk,
// which strict SSE endpoints reject.
func TestBodilessGETIsForwardedWithNoBodyFraming(t *testing.T) {
	seen := make(chan http.Header, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Clone()
		h.Set("X-Test-Transfer-Encoding", strings.Join(r.TransferEncoding, ","))
		h.Set("X-Test-Content-Length", fmt.Sprint(r.ContentLength))
		seen <- h
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: message\ndata: {}\n\n")
	}))
	t.Cleanup(up.Close)

	logLoc := homedir.Under(t.TempDir(), "audit.jsonl")
	logger, err := audit.New(logLoc)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	m := &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "sse-agent"},
		MCP:      manifest.MCP{Servers: []manifest.MCPServer{{ID: "email", URL: up.URL}}},
	}
	g, err := New(m, nil, nil, logger, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	port, token, err := g.Bind("ssearun01", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })

	url := fmt.Sprintf("http://127.0.0.1:%d/%s/servers/email", port, token)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("SSE GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SSE GET: status=%d, want 200", resp.StatusCode)
	}

	got := <-seen
	if te := got.Get("X-Test-Transfer-Encoding"); te != "" {
		t.Errorf("upstream saw Transfer-Encoding %q on a bodiless GET, want none", te)
	}
	if cl := got.Get("X-Test-Content-Length"); cl != "0" {
		t.Errorf("upstream saw ContentLength %s on a bodiless GET, want 0", cl)
	}
	if got.Get("Accept") != "text/event-stream" {
		t.Errorf("Accept header not forwarded: %q", got.Get("Accept"))
	}
}

// TestRefusedMethodIsNotLoggedBeforeAuthentication: the method check is an
// enforcement decision worth recording, but it runs only once a request has
// presented the gate token and named a declared server. An unauthenticated
// prober must not be able to drive audit writes.
func TestRefusedMethodIsNotLoggedBeforeAuthentication(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionApproved}, "abort")

	badToken := strings.Replace(h.baseURL, h.gate.token, strings.Repeat("0", 32), 1)
	if status, _, _ := doRequest(t, "PUT", badToken, ""); status != http.StatusNotFound {
		t.Errorf("PUT with a wrong token: status=%d, want 404", status)
	}
	badServer := strings.Replace(h.baseURL, "/servers/email", "/servers/other", 1)
	if status, _, _ := doRequest(t, "PUT", badServer, ""); status != http.StatusForbidden {
		t.Errorf("PUT to an undeclared server: status=%d, want 403", status)
	}

	if _, err := os.ReadFile(h.logPath); err == nil {
		if n := len(eventsOfType(auditEvents(t, h), audit.EventMCPRequestBlocked)); n != 0 {
			t.Errorf("unauthenticated probes wrote %d audit entries", n)
		}
	}
}

// chunkedRequest sends a request whose body is chunk-framed, so it arrives
// with no Content-Length and ContentLength -1. net/http's client uses chunked
// framing for any body whose length it cannot know in advance, which an
// io.Reader that is not one of its recognised types gives it.
func chunkedRequest(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	pr, pw := io.Pipe()
	go func() {
		if body != "" {
			_, _ = io.WriteString(pw, body)
		}
		_ = pw.Close()
	}()
	req, err := http.NewRequest(method, url, pr)
	if err != nil {
		t.Fatalf("%s %s: build: %v", method, url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Request != nil && resp.Request.ContentLength > 0 {
		t.Fatalf("%s was not sent chunked: ContentLength=%d", method, resp.Request.ContentLength)
	}
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

// TestChunkedBodyOnNonPOSTIsRefused closes the framing half of the bypass. A
// chunked request declares no length — ContentLength is -1, not the body size
// — so a gate that decided "does this carry a body?" from the declared length
// would read every chunked GET as empty and forward it, tool call and all.
// The decision must come from bytes actually read, and this pins that: the
// same gated call the Content-Length form is refused for must be refused when
// the length is withheld.
func TestChunkedBodyOnNonPOSTIsRefused(t *testing.T) {
	for _, method := range []string{"GET", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			h := newHarness(t, &fixedApprover{decision: DecisionApproved}, "abort")

			status, body := chunkedRequest(t, method, h.baseURL, toolCallBody("send_email"))
			if status != http.StatusBadRequest {
				t.Errorf("chunked %s carrying a gated tools/call: status=%d body=%s, want 400",
					method, status, body)
			}
			if h.calls.Load() != 0 {
				t.Errorf("chunked %s reached the upstream %d time(s)", method, h.calls.Load())
			}
			if n := len(eventsOfType(auditEvents(t, h), audit.EventMCPRequestBlocked)); n != 1 {
				t.Errorf("chunked %s: want 1 mcp_request_blocked, got %d", method, n)
			}
		})
	}
}

// TestChunkedEmptyBodyIsForwardedWithoutFraming is what the NoBody
// normalisation exists for. A GET whose body is chunk-framed but empty
// arrives with ContentLength -1 and a non-nil body, so without normalisation
// ReverseProxy forwards it still marked chunked and emits a lone terminating
// chunk on a GET — which strict SSE endpoints reject. Reading the body proves
// it empty; handing the proxy http.NoBody is what makes the forwarded request
// bodiless again.
//
// The request is written on a raw socket because net/http's client will not
// produce this shape: given a body of unknown length it probes the first read
// and, finding it empty, drops the chunked framing itself.
func TestChunkedEmptyBodyIsForwardedWithoutFraming(t *testing.T) {
	seen := make(chan []string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- append([]string{fmt.Sprint(r.ContentLength)}, r.TransferEncoding...)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: message\ndata: {}\n\n")
	}))
	t.Cleanup(up.Close)

	logLoc := homedir.Under(t.TempDir(), "audit.jsonl")
	logger, err := audit.New(logLoc)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	m := &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "sse-agent"},
		MCP:      manifest.MCP{Servers: []manifest.MCPServer{{ID: "email", URL: up.URL}}},
	}
	g, err := New(m, nil, nil, logger, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	port, token, err := g.Bind("chunkrun01", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, err = fmt.Fprintf(conn,
		"GET /%s/servers/email HTTP/1.1\r\nHost: %s\r\nAccept: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		token, addr)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chunk-framed empty GET: status=%d, want 200", resp.StatusCode)
	}

	select {
	case got := <-seen:
		if got[0] != "0" {
			t.Errorf("upstream saw ContentLength %s on a chunk-framed empty GET, want 0", got[0])
		}
		if len(got) > 1 {
			t.Errorf("upstream saw Transfer-Encoding %v on a chunk-framed empty GET, want none", got[1:])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the forwarded GET")
	}
}

// TestClampMethod: a method reaches the audit log, so its length is bounded
// there the way compactRPCID bounds a JSON-RPC id.
func TestClampMethod(t *testing.T) {
	if got := clampMethod("GET"); got != "GET" {
		t.Errorf("clampMethod(GET) = %q, want GET", got)
	}
	long := strings.Repeat("A", 500)
	if got := clampMethod(long); len(got) != 32 {
		t.Errorf("clampMethod(500 chars) length = %d, want 32", len(got))
	}
}

// TestNonPOSTBodyRefusalIsPinned fixes the shape of the refusal itself — the
// status an agent sees and the audit line an operator reads — so neither can
// drift into something less legible without a test saying so.
func TestNonPOSTBodyRefusalIsPinned(t *testing.T) {
	h := newHarness(t, &fixedApprover{decision: DecisionApproved}, "abort")

	status, body, _ := doRequest(t, "GET", h.baseURL, toolCallBody("send_email"))
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
	if !strings.Contains(body, "carries no MCP message") {
		t.Errorf("body = %q, want it to explain that GET carries no MCP message", body)
	}

	blocked := eventsOfType(auditEvents(t, h), audit.EventMCPRequestBlocked)
	if len(blocked) != 1 {
		t.Fatalf("want 1 mcp_request_blocked, got %d", len(blocked))
	}
	e := blocked[0]
	if e.RunID != "testrun01" || e.AgentName != "test-agent" {
		t.Errorf("attribution: run_id=%q agent=%q", e.RunID, e.AgentName)
	}
	if e.Details["server"] != "email" || e.Details["method"] != "GET" {
		t.Errorf("details = %+v", e.Details)
	}
	if _, leaked := e.Details["body"]; leaked {
		t.Error("the refused body must not be copied into the audit log")
	}
}

// TestApprovedCallIsTheCallTheOperatorSaw is the end-to-end form of the
// display fix, asserting the invariant the whole human gate rests on:
//
//	if the gate forwarded a tool call, the operator's transcript contained
//	every byte of what it forwarded.
//
// The old prompt printed a 500-byte prefix while forward() replayed the
// original body, so an agent could put a second, larger "amount_cents" past
// the window and have it be the one a last-key-wins parser used. Here the
// whole call goes through the real gate, the real TerminalApprover, and a
// real upstream that records exactly what it was asked to run.
func TestApprovedCallIsTheCallTheOperatorSaw(t *testing.T) {
	args := `{"destination_account":"ACH-SAFE-4417","amount_cents":4250,"memo":"` +
		strings.Repeat("routine monthly invoice. ", 30) +
		`","destination_account":"ACH-ATTACKER-9902","amount_cents":992450000}`

	inR, inW := io.Pipe()
	t.Cleanup(func() { _ = inW.Close(); _ = inR.Close() })
	out := newPromptWatcher()
	approver := &TerminalApprover{In: inR, Out: out, Interactive: true}

	h := newHarness(t, approver, "abort")
	h.gate.timeoutOverride = 5 * time.Second

	// Answer only once the prompt has actually been printed: the approver
	// drops input typed before a prompt exists (TestStaleKeystrokeDoes...),
	// so pre-loading the answer would be a flake, not a test.
	go func() {
		<-out.prompts
		_, _ = fmt.Fprintln(inW, "a")
	}()

	if status, body := postJSON(t, h.baseURL, toolCallBodyWithArgs("send_email", args)); status != 200 || !strings.Contains(body, "sent") {
		t.Fatalf("approved call: status=%d body=%s", status, body)
	}

	forwarded := h.bodies.last()
	if !strings.Contains(forwarded, "ACH-ATTACKER-9902") {
		t.Fatalf("harness bug: the upstream did not receive the hidden suffix, so this proves nothing:\n%s", forwarded)
	}

	out.mu.Lock()
	shown := out.buf.String()
	out.mu.Unlock()

	// Every token the upstream was asked to act on must appear in what the
	// operator read BEFORE they typed "a" — containment alone would also be
	// satisfied by printing the arguments after the answer was taken.
	promptAt := strings.Index(shown, "approve?")
	if promptAt < 0 {
		t.Fatalf("no approve prompt in the transcript:\n%s", shown)
	}
	for _, tok := range []string{"ACH-SAFE-4417", "ACH-ATTACKER-9902", "4250", "992450000"} {
		at := strings.Index(shown, tok)
		switch {
		case at < 0:
			t.Errorf("the gate forwarded %q but never showed it to the operator.\nprompt was:\n%s", tok, shown)
		case at > promptAt:
			t.Errorf("%q was printed only after the operator had already answered", tok)
		}
	}
	if strings.Contains(shown, "…") {
		t.Errorf("the approved call was elided in the prompt:\n%s", shown)
	}

	// The digest the audit log records for this approval must be the one the
	// operator was shown, or the prompt and the record name different calls.
	digest, err := humangate.SubjectDigest("send_email", json.RawMessage(args))
	if err != nil {
		t.Fatalf("SubjectDigest: %v", err)
	}
	if at := strings.Index(shown, digest); at < 0 || at > promptAt {
		t.Errorf("the subject digest %s was not shown to the operator before they answered:\n%s", digest, shown)
	}
}

// TestOversizedArgumentsAreNeverApproved: when the arguments cannot be shown
// in full, no keystroke may approve them. "Show everything" is only a real
// guarantee if the case it cannot serve fails closed rather than quietly
// falling back to a prefix.
//
// The answers are pre-loaded on purpose — the opposite of the test above.
// Nothing must approve this call, so an input already primed with every
// accepted approval word is the stronger setup, not a racy one.
func TestOversizedArgumentsAreNeverApproved(t *testing.T) {
	args := `{"pad":"` + strings.Repeat("x", maxDisplayedArgumentBytes+1000) + `","rm_rf":true}`

	var out strings.Builder
	approver := &TerminalApprover{
		In:          strings.NewReader("a\napprove\ny\nyes\n"), // would approve IF accepted
		Out:         &out,
		Interactive: true,
	}

	aborted := &atomic.Bool{}
	h := newHarness(t, approver, "abort")
	h.gate.SetAbortRun(func() { aborted.Store(true) })

	start := time.Now()
	status, body := postJSON(t, h.baseURL, toolCallBodyWithArgs("send_email", args))
	elapsed := time.Since(start)

	if status != 200 || !strings.Contains(body, "timed out") {
		t.Fatalf("oversized gate: status=%d body=%s", status, body)
	}
	if h.calls.Load() != 0 {
		t.Errorf("a call too large to display reached the upstream: %d calls", h.calls.Load())
	}
	if !aborted.Load() {
		t.Error("an undisplayable call must resolve by on_timeout=abort, not silently pass")
	}

	// The gate must cost the agent the full approval window. An early return
	// here would let an agent pad its arguments to skip straight to
	// on_timeout, which under proceed is the whole call. Mirrors the same
	// assertion in TestNonInteractiveStdinFallsThroughToTimeout.
	if elapsed < 150*time.Millisecond {
		t.Errorf("undisplayable gate resolved in %v — padding must not shortcut the timeout", elapsed)
	}

	shown := out.String()
	if !strings.Contains(shown, "over the 4096-byte limit") {
		t.Errorf("the operator was not told why the call could not be shown:\n%s", shown)
	}
	if strings.Contains(shown, "[a]pprove") {
		t.Errorf("an approve option was offered for arguments that were never shown:\n%s", shown)
	}
	if !strings.Contains(shown, "cannot approve arguments that were never shown") {
		t.Errorf("typing approve must be refused with a reason:\n%s", shown)
	}

	// Exactly one terminal event, and it is the honest one: the terminal did
	// not decide, so nothing may be recorded as a human decision.
	entries := auditEvents(t, h)
	if n := len(eventsOfType(entries, audit.EventGateTimeout)); n != 1 {
		t.Errorf("want 1 gate_timeout, got %d in %+v", n, entries)
	}
	for _, et := range []audit.EventType{audit.EventGateApproved, audit.EventGateDenied} {
		if n := len(eventsOfType(entries, et)); n != 0 {
			t.Errorf("got %d %s events for a gate no human answered", n, et)
		}
	}
}

// TestUndisplayableCallCanStillBeDenied is the other half of the rule, and
// the one that stops the refusal from becoming a weapon. Withdrawing the
// approve option must not withdraw the operator's veto: an agent that could
// silence the prompt by padding its arguments would gain the power to make a
// call undeniable, which under on_timeout=proceed is the whole call.
//
// Both policies are covered because they fail differently: under abort a lost
// veto merely delays the inevitable, under proceed it hands the agent the
// call outright.
func TestUndisplayableCallCanStillBeDenied(t *testing.T) {
	args := `{"pad":"` + strings.Repeat("x", maxDisplayedArgumentBytes+1000) +
		`","destination_account":"ACH-ATTACKER-9902"}`

	for _, onTimeout := range []string{"abort", "proceed"} {
		t.Run("on_timeout="+onTimeout, func(t *testing.T) {
			inR, inW := io.Pipe()
			t.Cleanup(func() { _ = inW.Close(); _ = inR.Close() })
			out := newDenyPromptWatcher()
			approver := &TerminalApprover{In: inR, Out: out, Interactive: true}

			aborted := &atomic.Bool{}
			h := newHarness(t, approver, onTimeout)
			h.gate.timeoutOverride = 5 * time.Second
			h.gate.SetAbortRun(func() { aborted.Store(true) })

			go func() {
				<-out.prompts
				_, _ = fmt.Fprintln(inW, "d")
			}()

			status, body := postJSON(t, h.baseURL, toolCallBodyWithArgs("send_email", args))
			if status != 200 || !strings.Contains(body, "DENIED") {
				t.Fatalf("deny of an undisplayable call: status=%d body=%s", status, body)
			}
			if h.calls.Load() != 0 {
				t.Errorf("a denied call reached the upstream: %d calls", h.calls.Load())
			}
			if aborted.Load() {
				t.Error("an explicit deny must not abort the run — only a timeout does")
			}
			if n := len(eventsOfType(auditEvents(t, h), audit.EventGateDenied)); n != 1 {
				t.Errorf("want 1 gate_denied, got %d", n)
			}
		})
	}
}

// denyPromptWatcher signals on the deny-only prompt, the way promptWatcher
// does for the ordinary one.
func newDenyPromptWatcher() *promptWatcher {
	p := newPromptWatcher()
	p.match = "[d]eny?"
	return p
}

// TestRenderBudgetsBoundWhatReachesTheTerminal: the raw-byte cap alone does
// not bound the display. json.Indent emits 3+2*depth spaces per line, so
// rendered size grows with the square of nesting depth — 4 KiB of brackets
// renders to megabytes across thousands of lines, scrolling the header, the
// subject digest and the first key out of any terminal's scrollback while
// every line is, technically, printed. Each budget is pinned by the payload
// that defeats the others.
func TestRenderBudgetsBoundWhatReachesTheTerminal(t *testing.T) {
	cases := []struct {
		name, args, wantReason string
	}{
		{
			// 191 raw bytes, 191 lines — under both the raw and the line
			// budget — rendering to 19 KB of indentation. Only the rendered
			// byte budget catches this one.
			"deep nesting inflates rendered bytes",
			strings.Repeat("[", 95) + "1" + strings.Repeat("]", 95),
			"bytes of text",
		},
		{
			"very deep nesting is many lines as well",
			strings.Repeat("[", 1200) + "1" + strings.Repeat("]", 1200),
			"lines",
		},
		{
			"a flat array is one line per element",
			"[" + strings.TrimSuffix(strings.Repeat("1,", 1500), ",") + "]",
			"lines",
		},
		{
			"raw size alone",
			`{"pad":"` + strings.Repeat("x", maxDisplayedArgumentBytes+10) + `"}`,
			"bytes, over the",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			approver := &TerminalApprover{In: strings.NewReader(""), Out: &out, Interactive: false}
			h := newHarness(t, approver, "abort")
			h.gate.SetAbortRun(func() {})

			postJSON(t, h.baseURL, toolCallBodyWithArgs("send_email", tc.args))

			if h.calls.Load() != 0 {
				t.Errorf("an undisplayable call reached the upstream: %d calls", h.calls.Load())
			}
			if !strings.Contains(out.String(), tc.wantReason) {
				t.Errorf("refusal reason missing %q; got:\n%s", tc.wantReason, out.String())
			}
			if n := len(out.String()); n > 4096 {
				t.Errorf("the refusal itself printed %d bytes — a refusal must be small", n)
			}
		})
	}
}

// TestGateEventsCarrySubjectDigest: gate_approved on its own records that
// something was approved, not what — and tool arguments themselves must never
// be copied into the audit log. The subject_digest is the one short value that
// closes that gap, and it is the same digest spec/human-gates-webhook.md §5
// has an approver sign, so a terminal approval and a webhook approval of the
// same call name the same subject.
func TestGateEventsCarrySubjectDigest(t *testing.T) {
	const args = `{"to":"x@example.com"}`

	want, err := humangate.SubjectDigest("send_email", json.RawMessage(args))
	if err != nil {
		t.Fatalf("SubjectDigest: %v", err)
	}

	h := newHarness(t, &fixedApprover{decision: DecisionApproved}, "abort")
	if status, _ := postJSON(t, h.baseURL, toolCallBodyWithArgs("send_email", args)); status != 200 {
		t.Fatalf("approved call: status=%d", status)
	}

	for _, et := range []audit.EventType{audit.EventGateTriggered, audit.EventGateApproved} {
		found := eventsOfType(auditEvents(t, h), et)
		if len(found) != 1 {
			t.Fatalf("want 1 %s, got %d", et, len(found))
		}
		if got := found[0].Details["subject_digest"]; got != want {
			t.Errorf("%s subject_digest = %v, want %v", et, got, want)
		}
	}
}

// TestDeniedAndTimedOutGatesCarrySubjectDigest: the digest has to identify
// the call on every terminal event, not only the approvals — a disputed
// denial needs the same forensic handle an approval does.
func TestDeniedAndTimedOutGatesCarrySubjectDigest(t *testing.T) {
	const args = `{"to":"x@example.com"}`
	want, err := humangate.SubjectDigest("send_email", json.RawMessage(args))
	if err != nil {
		t.Fatalf("SubjectDigest: %v", err)
	}

	cases := []struct {
		name     string
		approver Approver
		event    audit.EventType
	}{
		{"denied", &fixedApprover{decision: DecisionDenied}, audit.EventGateDenied},
		{"timeout", &fixedApprover{decision: DecisionApproved, delay: time.Hour}, audit.EventGateTimeout},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.approver, "abort")
			h.gate.SetAbortRun(func() {})
			postJSON(t, h.baseURL, toolCallBodyWithArgs("send_email", args))

			found := eventsOfType(auditEvents(t, h), tc.event)
			if len(found) != 1 {
				t.Fatalf("want 1 %s, got %d", tc.event, len(found))
			}
			if got := found[0].Details["subject_digest"]; got != want {
				t.Errorf("%s subject_digest = %v, want %v", tc.event, got, want)
			}
		})
	}
}
