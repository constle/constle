package a2a

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/constle/constle/internal/audit"
)

// ============================================================
// listener.go — the host-facing public side of A2A (a2a.listen)
//
// This is the project's first listener reachable from other machines, so it
// is categorically new attack surface: everything before it ran on
// sandbox-only-reachable addresses. A crash or hang here takes down the
// host constle process supervising the run — not a disposable sandbox — so
// the listener is hardened independently of (and before) any signature
// work:
//
//   1. Exact route match: POST /a2a/v1/call is the only served request;
//      everything else is a flat 404 with no body echo.
//   2. Hard server timeouts (header read, body read, write) so a slow or
//      stalling client cannot pin connections open indefinitely.
//   3. Body size cap enforced BEFORE any parsing: an oversized request is
//      rejected on byte count alone.
//   4. Malformed input (bad JSON, bad framing, bad base64, bad DID) is
//      rejected via error returns — no panics, and net/http's per-connection
//      recovery contains anything unexpected without killing the process.
//
// Only after all of that does verification run, in a fixed order — envelope
// signature (Open), sender ∈ declared peers, correct recipient, replay —
// and only a call that passes EVERY check is parked in the inbox the
// sandboxed agent drains. The sandbox is structurally unreachable from
// here: there is no code path from this listener to the sandbox except
// through the inbox, and nothing enters the inbox unverified.
// ============================================================

const (
	// perPeerInboxCapacity bounds how many verified-but-undelivered calls
	// the host holds PER DECLARED PEER. The quota is per peer, not shared:
	// a noisy (or buggy) — but fully authenticated — peer that fills its
	// own quota is shed with 503 without affecting an unrelated peer's
	// calls, so one trusted peer cannot starve another. The delivery
	// channel's total capacity is the sum of all quotas, which is why
	// admission under quota can never block on the channel itself.
	perPeerInboxCapacity = 16

	// replyTimeout bounds how long the public listener holds a peer's
	// connection open waiting for the sandboxed agent to answer. Shorter
	// than the sender side's callTimeout so the caller sees our 504, not
	// its own client timeout.
	replyTimeout = 90 * time.Second

	// inboxPollTimeout is the long-poll window of GET /{token}/inbox; the
	// agent re-polls on 204.
	inboxPollTimeout = 25 * time.Second

	// publicMaxHeaderBytes caps request headers on the public listener.
	publicMaxHeaderBytes = 16 << 10
)

// inboundCall is one fully verified call parked for the sandboxed agent.
type inboundCall struct {
	env      *Envelope
	peerName string

	// respCh carries the signed response wire from the reply handler to
	// the public-listener goroutine holding the peer's connection.
	// Buffered so a reply landing after the peer-side timeout is dropped
	// instead of leaking a goroutine.
	respCh chan []byte
}

// StartListener binds the public A2A listener on addr and serves it until
// Close. Called by the CLI only when the manifest sets a2a.listen.
func (g *Gate) StartListener(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot bind A2A listener on %s: %w", addr, err)
	}

	g.public = &http.Server{
		Handler:           http.HandlerFunc(g.servePublic),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      replyTimeout + 30*time.Second,
		MaxHeaderBytes:    publicMaxHeaderBytes,
	}
	go g.public.Serve(ln)
	return nil
}

// servePublic handles one inbound call from a peer. Hardening and
// verification run in the order documented in the file header; the first
// failing step ends the request, and nothing sandbox-visible happens
// before the last verification step has passed.
func (g *Gate) servePublic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != CallPath {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Cap before parse: reject on byte count alone, no inspection.
	wire, err := readCapped(r.Body)
	if err != nil {
		g.logRejected("", "", "request", "", "", ReasonMalformed, err.Error())
		http.Error(w, "constle a2a: "+err.Error(), http.StatusRequestEntityTooLarge)
		return
	}

	// Signature and framing (Open fails closed on everything malformed).
	env, err := Open(wire)
	if err != nil {
		reason := ReasonMalformed
		if re, ok := err.(*RejectError); ok {
			reason = re.Reason
		}
		g.logRejected("", "", "request", "", "", reason, err.Error())
		http.Error(w, "constle a2a: envelope rejected", http.StatusForbidden)
		return
	}

	// Peer authorization: the sender DID must be explicitly declared.
	peer, ok := g.peersByDID[env.From]
	if !ok {
		g.logRejected("", env.From, "request", env.MsgID, "", ReasonUnknownPeer,
			fmt.Sprintf("sender %s is not a declared peer", env.From))
		http.Error(w, "constle a2a: sender is not a declared peer", http.StatusForbidden)
		return
	}

	// The call must be addressed to this agent, not relayed or misrouted.
	if env.To != g.signer.DID() {
		g.logRejected(peer.Name, env.From, "request", env.MsgID, "", ReasonWrongRecipient,
			fmt.Sprintf("call addressed to %s", env.To))
		http.Error(w, "constle a2a: call is not addressed to this agent", http.StatusForbidden)
		return
	}

	// Replay/staleness (in-memory, per-run — see replayGuard's limitation).
	if err := g.replay.check(env); err != nil {
		reason := ReasonReplay
		if re, ok := err.(*RejectError); ok {
			reason = re.Reason
		}
		g.logRejected(peer.Name, env.From, "request", env.MsgID, "", reason, err.Error())
		http.Error(w, "constle a2a: envelope rejected", http.StatusForbidden)
		return
	}

	// Every check passed — only now may the call become sandbox-visible.
	// Admission is bounded per peer (see perPeerInboxCapacity): exceeding
	// your own quota sheds only your calls, never another peer's.
	call := &inboundCall{env: env, peerName: peer.Name, respCh: make(chan []byte, 1)}
	g.mu.Lock()
	if g.inboxUsed[peer.Name] >= perPeerInboxCapacity {
		g.mu.Unlock()
		g.logRejected(peer.Name, env.From, "request", env.MsgID, "", ReasonInboxFull,
			fmt.Sprintf("peer %q has %d undelivered calls", peer.Name, perPeerInboxCapacity))
		http.Error(w, "constle a2a: this peer's inbox quota is full, retry later", http.StatusServiceUnavailable)
		return
	}
	g.inboxUsed[peer.Name]++
	g.mu.Unlock()
	// Never blocks: the channel's capacity is the sum of all peer quotas.
	g.inbox <- call

	g.log(audit.EventA2ACallReceived, map[string]any{
		"direction": "request",
		"peer":      peer.Name,
		"from_did":  env.From,
		"msg_id":    env.MsgID,
	})

	// Hold the peer's connection for the agent's signed reply.
	timeout := replyTimeout
	if g.replyTimeoutOverride > 0 {
		timeout = g.replyTimeoutOverride
	}
	select {
	case respWire := <-call.respCh:
		w.Header().Set("Content-Type", "application/json")
		w.Write(respWire)
	case <-time.After(timeout):
		// The round trip died on the response leg: our agent never
		// answered. Recorded so this log alone tells the whole story.
		g.expireCall(env.MsgID)
		g.logRejected(peer.Name, "", "response", "", env.MsgID, ReasonReplyTimeout,
			fmt.Sprintf("agent did not answer within %s", timeout))
		http.Error(w, "constle a2a: agent did not answer in time", http.StatusGatewayTimeout)
	case <-r.Context().Done():
		// Peer hung up; stop tracking the call so a late reply gets a 404
		// instead of feeding a dead connection.
		g.expireCall(env.MsgID)
		g.logRejected(peer.Name, "", "response", "", env.MsgID, ReasonPeerDisconnected,
			"peer closed the connection before the reply was ready")
	}
}

// serveInbox long-polls the next verified call for the sandboxed agent:
// 200 with the plaintext body plus verified sender metadata headers, or
// 204 when the window closes empty. Only the verified payload crosses the
// boundary — the agent never sees the raw envelope or a signature.
func (g *Gate) serveInbox(w http.ResponseWriter, r *http.Request) {
	poll := inboxPollTimeout
	if g.pollTimeoutOverride > 0 {
		poll = g.pollTimeoutOverride
	}

	select {
	case call := <-g.inbox:
		g.mu.Lock()
		g.pending[call.env.MsgID] = call
		g.inboxUsed[call.peerName]-- // delivered: frees the peer's quota slot
		g.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Constle-A2A-From", call.env.From)
		w.Header().Set("X-Constle-A2A-Peer", call.peerName)
		w.Header().Set("X-Constle-A2A-Msg-Id", call.env.MsgID)
		w.Write(call.env.Body)

	case <-time.After(poll):
		w.WriteHeader(http.StatusNoContent)

	case <-r.Context().Done():
	}
}

// serveReply accepts the agent's answer to a delivered call, signs it with
// the agent's identity (bound to the request via in_reply_to), and hands it
// to the public-listener goroutine still holding the peer's connection.
func (g *Gate) serveReply(w http.ResponseWriter, r *http.Request, msgID string) {
	body, err := readCapped(r.Body)
	if err != nil {
		http.Error(w, "constle a2a gate: "+err.Error(), http.StatusRequestEntityTooLarge)
		return
	}

	g.mu.Lock()
	call, ok := g.pending[msgID]
	delete(g.pending, msgID)
	g.mu.Unlock()
	if !ok {
		http.Error(w, "constle a2a gate: no pending call with this msg_id (unknown, already answered, or timed out)", http.StatusNotFound)
		return
	}

	respWire, sealedResp, err := Seal(g.signer, call.env.From, call.env.MsgID, body)
	if err != nil {
		// The call stays consumed: a reply the host cannot sign is not
		// retried with a different body against the same envelope.
		http.Error(w, "constle a2a gate: "+err.Error(), http.StatusBadRequest)
		return
	}

	call.respCh <- respWire

	// A signed envelope is leaving this host: the response leg of the
	// round trip, completing the symmetric sent/received pairing.
	g.log(audit.EventA2ACallSent, map[string]any{
		"direction":   "response",
		"peer":        call.peerName,
		"to_did":      call.env.From,
		"msg_id":      sealedResp.MsgID,
		"in_reply_to": call.env.MsgID,
	})
	w.WriteHeader(http.StatusNoContent)
}

// expireCall stops tracking a call whose peer connection is gone, so a
// late agent reply cannot match it anymore.
func (g *Gate) expireCall(msgID string) {
	g.mu.Lock()
	delete(g.pending, msgID)
	g.mu.Unlock()
}

// logRejected writes one a2a_call_rejected audit entry: "this round trip
// did not complete, for reason X" — verification failures and transport
// failures alike. direction names the envelope leg the failure concerns
// ("request" or "response"). Empty fields are omitted; claimedDID carries
// the sender DID asserted by an envelope that failed authorization, which
// is claimed, not verified attribution.
func (g *Gate) logRejected(peerName, claimedDID, direction, msgID, inReplyTo string, reason RejectReason, detail string) {
	details := map[string]any{
		"direction": direction,
		"reason":    string(reason),
		"detail":    detail,
	}
	if peerName != "" {
		details["peer"] = peerName
	}
	if claimedDID != "" {
		details["claimed_did"] = claimedDID
	}
	if msgID != "" {
		details["msg_id"] = msgID
	}
	if inReplyTo != "" {
		details["in_reply_to"] = inReplyTo
	}
	g.log(audit.EventA2ACallRejected, details)
}
