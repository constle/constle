package mcpgate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/humangate"
)

// decisionResponseCap bounds how much of a decision-poll response body this
// approver reads — a decision is a few hundred bytes; anything wildly larger
// is not a body worth trusting.
const decisionResponseCap = 64 << 10 // 64 KiB

// defaultPollInterval paces both decision polling and gate-open retries when
// no override is set.
const defaultPollInterval = 2 * time.Second

// WebhookApprover asks an external decision endpoint for a gate's outcome,
// per spec/human-gates-webhook.md, and verifies the signed answer with
// humangate.VerifyDecision before ever treating a gated call as approved.
//
// It is one possible input to a gate among others (see RaceApprover) —
// nothing about this type assumes it is the only approver configured — and
// it never blocks past the ctx it is given: every outbound request derives
// its own deadline from that ctx, so a gate's approval_timeout_seconds is
// the one and only deadline this approver ever needs to know about.
type WebhookApprover struct {
	// URL is the configured decision-endpoint address — the same
	// human_gates.notify webhook URL that already receives gate-triggered
	// notifications (spec §4.1).
	URL string

	// ApproverPubkey is the Agentfile's human_gates.approver_pubkey.
	ApproverPubkey string

	// Client defaults to http.DefaultClient. Every request is bounded by
	// the ctx passed to Decide/DecideWithReason, not by a fixed client
	// timeout.
	Client *http.Client

	// Out receives delivery warnings, matching WebhookNotifier's pattern.
	// Nil discards them.
	Out io.Writer

	// PollInterval paces retries of the gate-open POST and of decision
	// polling. Defaults to defaultPollInterval; overridable in tests.
	PollInterval time.Duration
}

// gateRequestWire is spec §4's outbound request body.
type gateRequestWire struct {
	RequestID     string       `json:"request_id"`
	AgentName     string       `json:"agent_name"`
	ToolCall      toolCallWire `json:"tool_call"`
	SubjectDigest string       `json:"subject_digest"`
	Timestamp     time.Time    `json:"timestamp"`
}

type toolCallWire struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// Decide implements Approver.
func (w *WebhookApprover) Decide(ctx context.Context, req Request) Decision {
	return w.DecideWithReason(ctx, req).Decision
}

// DecideWithReason implements ReasoningApprover: it opens the gate on the
// configured decision endpoint, polls for a decision until one arrives or
// ctx ends, and verifies whatever arrives before ever returning
// DecisionApproved.
func (w *WebhookApprover) DecideWithReason(ctx context.Context, req Request) Outcome {
	args := req.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	subjectDigest, err := humangate.SubjectDigest(req.Tool, args)
	if err != nil {
		// The gate proxy only reaches here for a tool call it already
		// parsed as valid JSON-RPC, so this is unreachable in practice —
		// but a digest we cannot compute is a request we cannot build, and
		// that must deny, not panic or silently skip verification.
		w.warn("cannot compute subject_digest: %v", err)
		return Outcome{Decision: DecisionDenied, DecidedBy: "webhook"}
	}

	requestID := newRequestID()
	body, err := json.Marshal(gateRequestWire{
		RequestID:     requestID,
		AgentName:     req.AgentName,
		ToolCall:      toolCallWire{Name: req.Tool, Arguments: args},
		SubjectDigest: subjectDigest,
		Timestamp:     time.Now().UTC(),
	})
	if err != nil {
		w.warn("cannot build gate request: %v", err)
		return Outcome{Decision: DecisionDenied, DecidedBy: "webhook"}
	}

	decisionURL := strings.TrimSuffix(w.URL, "/") + "/" + requestID + "/decision"

	interval := w.PollInterval
	if interval <= 0 {
		interval = defaultPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	posted := false
	for {
		if !posted {
			if w.post(ctx, body) {
				posted = true
			} else {
				w.warn("delivery of the gate request failed; will retry")
			}
		}

		// The decision endpoint is derivable without a successful POST
		// (spec §4.1): a receiver that has not yet seen the request simply
		// has no decision yet, which polling discovers the same way a
		// delivery failure does — no special case needed here.
		if resp, ok := w.poll(ctx, decisionURL); ok {
			return w.verify(subjectDigest, resp)
		}

		select {
		case <-ctx.Done():
			return Outcome{Decision: DecisionNone}
		case <-ticker.C:
		}
	}
}

// verify applies humangate.VerifyDecision and maps its Reason onto the
// specific audit event the fail-closed table calls for. approved is never
// true unless VerifyDecision says so.
func (w *WebhookApprover) verify(subjectDigest string, resp humangate.DecisionResponse) Outcome {
	approved, reason, err := humangate.VerifyDecision(w.ApproverPubkey, subjectDigest, resp)
	switch {
	case approved:
		return Outcome{Decision: DecisionApproved, DecidedBy: "webhook"}
	case reason == humangate.ReasonSignatureInvalid:
		w.warn("decision signature did not verify: %v", err)
		return Outcome{Decision: DecisionDenied, DecidedBy: "webhook", Event: audit.EventGateSignatureInvalid}
	case reason == humangate.ReasonDigestMismatch:
		w.warn("decision subject_digest did not match the request: %v", err)
		return Outcome{Decision: DecisionDenied, DecidedBy: "webhook", Event: audit.EventGateDigestMismatch}
	default:
		return Outcome{Decision: DecisionDenied, DecidedBy: "webhook"}
	}
}

func (w *WebhookApprover) client() *http.Client {
	if w.Client != nil {
		return w.Client
	}
	return http.DefaultClient
}

// post delivers the gate-open request once. Its own failure is never fatal
// to DecideWithReason — decision polling proceeds regardless (spec §4.1) —
// so this only reports whether delivery succeeded.
func (w *WebhookApprover) post(ctx context.Context, body []byte) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client().Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// poll fetches the decision endpoint once. ok is true only when a decision
// body actually came back (HTTP 200 with a parseable body) — any other
// status (202, 404, 5xx, ...) means "not yet", not an error, and the caller
// keeps polling within its own ctx budget.
func (w *WebhookApprover) poll(ctx context.Context, url string) (humangate.DecisionResponse, bool) {
	var zero humangate.DecisionResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return zero, false
	}
	resp, err := w.client().Do(req)
	if err != nil {
		return zero, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return zero, false
	}

	var out humangate.DecisionResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, decisionResponseCap)).Decode(&out); err != nil {
		return zero, false
	}
	return out, true
}

func (w *WebhookApprover) warn(format string, args ...any) {
	if w.Out == nil {
		return
	}
	outf(w.Out, "⚠️  warning: human-gates webhook: "+format+"\n", args...)
}

// newRequestID mints a fresh request_id (spec §4's own example format:
// "hg_" plus random hex) — unique per gate, never reused, so a decision
// signed for one request_id can never be mistaken for a decision about a
// different tool call even if two calls happen to share a subject_digest.
func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read failing is a broken host, not a normal error
		// path; a timestamp-based fallback still keeps request_id unique
		// enough for this to fail closed (via decision correlation
		// mismatches) rather than panic.
		return fmt.Sprintf("hg_%x", time.Now().UnixNano())
	}
	return "hg_" + hex.EncodeToString(b)
}
