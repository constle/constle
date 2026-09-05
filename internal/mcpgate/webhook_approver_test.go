package mcpgate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/humangate"
	"github.com/constle/constle/pkg/did"
)

// fakeDecisionEndpoint is a real HTTP server standing in for a
// spec/human-gates-webhook.md decision endpoint: it accepts the gate-open
// POST, then answers the derived .../decision GET according to a
// test-controlled decision function.
type fakeDecisionEndpoint struct {
	server *httptest.Server

	mu       sync.Mutex
	posts    int
	lastPost gateRequestWire
	decide   func(req gateRequestWire) (humangate.DecisionResponse, bool) // ok=false => still pending
}

func newFakeDecisionEndpoint(t *testing.T) *fakeDecisionEndpoint {
	t.Helper()
	f := &fakeDecisionEndpoint{}
	mux := http.NewServeMux()
	mux.HandleFunc("/gate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body gateRequestWire
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.posts++
		f.lastPost = body
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/gate/", func(w http.ResponseWriter, r *http.Request) {
		// /gate/<request_id>/decision
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/gate/"), "/")
		if len(parts) != 2 || parts[1] != "decision" {
			http.NotFound(w, r)
			return
		}
		requestID := parts[0]

		f.mu.Lock()
		fn := f.decide
		lastPost := f.lastPost
		f.mu.Unlock()
		if fn == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		resp, ok := fn(gateRequestWire{RequestID: requestID, AgentName: lastPost.AgentName, ToolCall: lastPost.ToolCall, SubjectDigest: lastPost.SubjectDigest})
		if !ok {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeDecisionEndpoint) url() string { return f.server.URL + "/gate" }

func (f *fakeDecisionEndpoint) postCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.posts
}

// testApprover is a real Ed25519 keypair standing in for the approver.
type testApprover struct {
	priv ed25519.PrivateKey
	did  string
}

func newTestApprover(t *testing.T) testApprover {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	d, err := did.FromPublicKey(pub)
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}
	return testApprover{priv: priv, did: d}
}

func (a testApprover) sign(requestID, decision, subjectDigest string) string {
	payload := []byte(requestID + "." + decision + "." + subjectDigest)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(a.priv, payload))
}

func newTestRequest(tool string, args string) Request {
	return Request{
		RunID:     "run-1",
		AgentName: "agent-1",
		ServerID:  "srv",
		Tool:      tool,
		Arguments: json.RawMessage(args),
	}
}

func TestWebhookApproverApprovesOnValidSignedDecision(t *testing.T) {
	approver := newTestApprover(t)
	endpoint := newFakeDecisionEndpoint(t)

	var polls atomic.Int32
	endpoint.decide = func(req gateRequestWire) (humangate.DecisionResponse, bool) {
		n := polls.Add(1)
		if n < 2 {
			return humangate.DecisionResponse{}, false // pending on the first poll
		}
		sig := approver.sign(req.RequestID, "approved", req.SubjectDigest)
		return humangate.DecisionResponse{
			RequestID: req.RequestID, Decision: "approved",
			SubjectDigest: req.SubjectDigest, Signature: sig, DecidedAt: time.Now().UTC(),
		}, true
	}

	wa := &WebhookApprover{
		URL: endpoint.url(), ApproverPubkey: approver.did,
		PollInterval: 10 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	outcome := wa.DecideWithReason(ctx, newTestRequest("send_email", `{"to":"x@example.com"}`))
	if outcome.Decision != DecisionApproved {
		t.Fatalf("Decision = %v, want DecisionApproved", outcome.Decision)
	}
	if outcome.DecidedBy != "webhook" {
		t.Errorf("DecidedBy = %q, want webhook", outcome.DecidedBy)
	}
	if endpoint.postCount() < 1 {
		t.Error("gate-open POST was never delivered")
	}
}

func TestWebhookApproverDeniesOnExplicitDenial(t *testing.T) {
	approver := newTestApprover(t)
	endpoint := newFakeDecisionEndpoint(t)
	endpoint.decide = func(req gateRequestWire) (humangate.DecisionResponse, bool) {
		sig := approver.sign(req.RequestID, "denied", req.SubjectDigest)
		return humangate.DecisionResponse{
			RequestID: req.RequestID, Decision: "denied",
			SubjectDigest: req.SubjectDigest, Signature: sig,
		}, true
	}

	wa := &WebhookApprover{URL: endpoint.url(), ApproverPubkey: approver.did, PollInterval: 10 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	outcome := wa.DecideWithReason(ctx, newTestRequest("send_email", `{}`))
	if outcome.Decision != DecisionDenied {
		t.Fatalf("Decision = %v, want DecisionDenied", outcome.Decision)
	}
	if outcome.Event != "" {
		t.Errorf("Event = %q, want no override for an ordinary denial", outcome.Event)
	}
}

func TestWebhookApproverTimesOutWithNoDecision(t *testing.T) {
	approver := newTestApprover(t)
	endpoint := newFakeDecisionEndpoint(t)
	// decide left nil: every poll returns 202 pending, forever.

	wa := &WebhookApprover{URL: endpoint.url(), ApproverPubkey: approver.did, PollInterval: 20 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	outcome := wa.DecideWithReason(ctx, newTestRequest("send_email", `{}`))
	if outcome.Decision != DecisionNone {
		t.Fatalf("Decision = %v, want DecisionNone (timeout)", outcome.Decision)
	}
}

func TestWebhookApproverRejectsInvalidSignature(t *testing.T) {
	approver := newTestApprover(t)
	other := newTestApprover(t)
	endpoint := newFakeDecisionEndpoint(t)
	endpoint.decide = func(req gateRequestWire) (humangate.DecisionResponse, bool) {
		// Signed with the WRONG key.
		sig := other.sign(req.RequestID, "approved", req.SubjectDigest)
		return humangate.DecisionResponse{
			RequestID: req.RequestID, Decision: "approved",
			SubjectDigest: req.SubjectDigest, Signature: sig,
		}, true
	}

	wa := &WebhookApprover{URL: endpoint.url(), ApproverPubkey: approver.did, PollInterval: 10 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	outcome := wa.DecideWithReason(ctx, newTestRequest("send_email", `{}`))
	if outcome.Decision != DecisionDenied {
		t.Fatalf("Decision = %v, want DecisionDenied", outcome.Decision)
	}
	if outcome.Event != audit.EventGateSignatureInvalid {
		t.Errorf("Event = %q, want %q", outcome.Event, audit.EventGateSignatureInvalid)
	}
}

func TestWebhookApproverRejectsDigestMismatch(t *testing.T) {
	approver := newTestApprover(t)
	endpoint := newFakeDecisionEndpoint(t)
	endpoint.decide = func(req gateRequestWire) (humangate.DecisionResponse, bool) {
		staleDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		sig := approver.sign(req.RequestID, "approved", staleDigest)
		return humangate.DecisionResponse{
			RequestID: req.RequestID, Decision: "approved",
			SubjectDigest: staleDigest, Signature: sig,
		}, true
	}

	wa := &WebhookApprover{URL: endpoint.url(), ApproverPubkey: approver.did, PollInterval: 10 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	outcome := wa.DecideWithReason(ctx, newTestRequest("send_email", `{}`))
	if outcome.Decision != DecisionDenied {
		t.Fatalf("Decision = %v, want DecisionDenied", outcome.Decision)
	}
	if outcome.Event != audit.EventGateDigestMismatch {
		t.Errorf("Event = %q, want %q", outcome.Event, audit.EventGateDigestMismatch)
	}
}

func TestWebhookApproverSurvivesFailedInitialPost(t *testing.T) {
	approver := newTestApprover(t)
	// URL that accepts no POST at all (404 on everything) until the decision
	// sub-path answers — proving polling proceeds even when the open POST
	// never lands (spec §4.1: the decision endpoint is derivable without it).
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/gate", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "nope", http.StatusInternalServerError)
	})
	mux.HandleFunc("/gate/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/gate/"), "/")
		requestID := parts[0]
		sig := approver.sign(requestID, "approved", wantDigestForEmptyArgs(t))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(humangate.DecisionResponse{
			RequestID: requestID, Decision: "approved",
			SubjectDigest: wantDigestForEmptyArgs(t), Signature: sig,
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	wa := &WebhookApprover{URL: srv.URL + "/gate", ApproverPubkey: approver.did, PollInterval: 10 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	outcome := wa.DecideWithReason(ctx, newTestRequest("noop", `{}`))
	if outcome.Decision != DecisionApproved {
		t.Fatalf("Decision = %v, want DecisionApproved despite a failing POST", outcome.Decision)
	}
	if hits.Load() == 0 {
		t.Error("expected at least one POST retry attempt")
	}
}

func wantDigestForEmptyArgs(t *testing.T) string {
	t.Helper()
	d, err := humangate.SubjectDigest("noop", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("SubjectDigest: %v", err)
	}
	return d
}

func TestNewRequestIDIsUniqueAndPrefixed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := newRequestID()
		if !strings.HasPrefix(id, "hg_") {
			t.Fatalf("request id %q missing hg_ prefix", id)
		}
		if seen[id] {
			t.Fatalf("duplicate request id %q", id)
		}
		seen[id] = true
	}
}
