package a2a

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/pkg/manifest"
)

// maxBodyBytes caps every body this package reads — sandbox requests to the
// gate AND peer traffic on the public listener. Oversized input fails closed
// before any parsing or signature work.
const maxBodyBytes = 10 << 20 // 10 MB

// CallPath is the path on a peer's public listener that receives signed
// envelopes. Outbound calls POST to <peer.endpoint>+CallPath; the inbound
// listener serves exactly this path and nothing else.
const CallPath = "/a2a/v1/call"

// callTimeout bounds one whole outbound exchange: dialing the peer's host,
// the peer's own agent handling the request, and the signed response coming
// back. Generous because a peer's reply may itself wait on agent work.
const callTimeout = 120 * time.Second

// Gate is the per-run A2A gate: the sandbox-facing proxy that signs
// outbound calls with the agent's identity and verifies peers' responses.
// Create with New, bind with Bind, close with Close. Safe for concurrent
// use once bound.
//
// The gate deliberately mirrors mcpgate.Gate: per-run URL token, ephemeral
// port bound on every candidate host IP, fail-closed routing.
type Gate struct {
	signer     Signer
	peers      map[string]manifest.A2APeer // by declared name
	peersByDID map[string]manifest.A2APeer // inbound authorization set
	logger     *audit.Logger
	client     *http.Client
	replay     *replayGuard

	// inbox holds verified inbound calls until the agent drains them;
	// inboxUsed counts undelivered calls per peer name (admission quota,
	// mu-guarded); pending tracks delivered calls awaiting the agent's
	// reply.
	inbox     chan *inboundCall
	inboxUsed map[string]int
	pending   map[string]*inboundCall

	mu        sync.Mutex
	runID     string
	agentName string

	token     string
	port      int
	listeners []net.Listener
	server    *http.Server
	public    *http.Server // host-facing listener (a2a.listen), see listener.go

	// test overrides (0 = production values).
	replyTimeoutOverride time.Duration
	pollTimeoutOverride  time.Duration
}

// New builds a Gate from the manifest's a2a.peers and the agent's identity.
// The signer must be the identity the manifest declares — a gate signing
// with any other key would make the declared identity a lie.
func New(m *manifest.AgentManifest, signer Signer, logger *audit.Logger) (*Gate, error) {
	if signer == nil {
		return nil, fmt.Errorf("a2a gate requires the agent's identity to sign with")
	}
	if signer.DID() != m.Identity.DID {
		return nil, fmt.Errorf("a2a gate identity mismatch: manifest declares %s but the loaded identity is %s",
			m.Identity.DID, signer.DID())
	}

	g := &Gate{
		signer:     signer,
		peers:      map[string]manifest.A2APeer{},
		peersByDID: map[string]manifest.A2APeer{},
		logger:     logger,
		client:     &http.Client{Timeout: callTimeout},
		replay:     newReplayGuard(),
		inbox:      make(chan *inboundCall, perPeerInboxCapacity*max(len(m.A2A.Peers), 1)),
		inboxUsed:  map[string]int{},
		pending:    map[string]*inboundCall{},
		agentName:  m.Identity.Name,
	}
	for _, p := range m.A2A.Peers {
		g.peers[p.Name] = p
		g.peersByDID[p.DID] = p
	}
	return g, nil
}

// Bind starts the gate's HTTP listener on every candidate IP that exists on
// this host, all on the same ephemeral port, and returns that port plus the
// per-run URL token — the exact contract of mcpgate.Gate.Bind, so backends
// route to it identically.
func (g *Gate) Bind(runID string, candidateIPs []string) (port int, token string, err error) {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return 0, "", fmt.Errorf("cannot generate a2a gate token: %w", err)
	}
	g.token = fmt.Sprintf("%x", tokenBytes)

	g.mu.Lock()
	g.runID = runID
	g.mu.Unlock()

	var listeners []net.Listener
	for _, ip := range candidateIPs {
		addr := net.JoinHostPort(ip, fmt.Sprint(port))
		ln, lnErr := net.Listen("tcp", addr)
		if lnErr != nil {
			// Candidate IP not present on this host — expected for the
			// network layout we are not running under.
			continue
		}
		listeners = append(listeners, ln)
		if port == 0 {
			port = ln.Addr().(*net.TCPAddr).Port
		}
	}
	if len(listeners) == 0 {
		return 0, "", fmt.Errorf("cannot bind A2A gate on any of %v", candidateIPs)
	}

	g.port = port
	g.listeners = listeners
	g.server = &http.Server{Handler: g}
	for _, ln := range listeners {
		go g.server.Serve(ln)
	}

	return port, g.token, nil
}

// Port returns the bound gate port (0 before Bind).
func (g *Gate) Port() int { return g.port }

// Close immediately shuts down the sandbox-facing gate and the public
// listener, aborting in-flight connections. Safe to call before Bind /
// StartListener and more than once.
func (g *Gate) Close() error {
	var err error
	if g.server != nil {
		err = g.server.Close()
	}
	if g.public != nil {
		if perr := g.public.Close(); err == nil {
			err = perr
		}
	}
	return err
}

// ServeHTTP routes the sandbox-facing API. Everything that cannot be
// positively matched — wrong token, unknown path, undeclared peer — fails
// closed with no fallback.
//
//	POST /{token}/send/{peer}  — sign body, deliver to the declared peer,
//	                             verify the signed response, return its body.
//	GET  /{token}/inbox        — long-poll the next verified inbound call.
//	POST /{token}/reply/{id}   — answer a delivered call; the host signs it.
func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/"+g.token+"/")
	if !ok {
		http.Error(w, "constle a2a gate: unknown path", http.StatusNotFound)
		return
	}

	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(rest, "send/"):
		g.serveSend(w, r, strings.TrimPrefix(rest, "send/"))
	case r.Method == http.MethodGet && rest == "inbox":
		g.serveInbox(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(rest, "reply/"):
		g.serveReply(w, r, strings.TrimPrefix(rest, "reply/"))
	default:
		http.Error(w, "constle a2a gate: unknown path", http.StatusNotFound)
	}
}

// serveSend handles one outbound call: the host signs the sandbox's JSON
// body with the agent's identity, POSTs it to the declared peer, verifies
// the peer's signed response, and hands only the verified body back.
func (g *Gate) serveSend(w http.ResponseWriter, r *http.Request, peerName string) {
	peer, ok := g.peers[peerName]
	if !ok {
		http.Error(w, fmt.Sprintf("constle a2a gate: peer %q is not declared in the Agentfile", peerName), http.StatusForbidden)
		return
	}

	body, err := readCapped(r.Body)
	if err != nil {
		http.Error(w, "constle a2a gate: "+err.Error(), http.StatusRequestEntityTooLarge)
		return
	}

	wire, sealed, err := Seal(g.signer, peer.DID, "", body)
	if err != nil {
		http.Error(w, "constle a2a gate: "+err.Error(), http.StatusBadRequest)
		return
	}

	g.log(audit.EventA2ACallSent, map[string]any{
		"direction": "request",
		"peer":      peerName,
		"to_did":    peer.DID,
		"msg_id":    sealed.MsgID,
	})

	resp, err := g.client.Post(peer.Endpoint+CallPath, "application/json", strings.NewReader(string(wire)))
	if err != nil {
		// The request envelope never made it out — without this entry the
		// sender's log would end at a2a_call_sent with no way to tell "the
		// peer went dark" from "completed on a log I cannot see".
		g.logRejected(peerName, "", "request", sealed.MsgID, "", ReasonPeerUnreachable, err.Error())
		http.Error(w, fmt.Sprintf("constle a2a gate: cannot reach peer %q: %v", peerName, err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respWire, err := readCapped(resp.Body)
	if err != nil {
		g.logRejected(peerName, "", "response", "", sealed.MsgID, ReasonPeerHTTPError, err.Error())
		http.Error(w, fmt.Sprintf("constle a2a gate: response from peer %q: %v", peerName, err), http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusOK {
		// The peer refused the call (or errored). Do not relay its body —
		// only the status reaches the sandbox.
		g.logRejected(peerName, "", "response", "", sealed.MsgID, ReasonPeerHTTPError,
			fmt.Sprintf("peer answered HTTP %d", resp.StatusCode))
		http.Error(w, fmt.Sprintf("constle a2a gate: peer %q refused the call (HTTP %d)", peerName, resp.StatusCode), http.StatusBadGateway)
		return
	}

	respEnv, err := g.verifyResponse(respWire, peer, sealed.MsgID)
	if err != nil {
		reason := ReasonMalformed
		if re, ok := err.(*RejectError); ok {
			reason = re.Reason
		}
		g.logRejected(peerName, "", "response", "", sealed.MsgID, reason, err.Error())
		http.Error(w, fmt.Sprintf("constle a2a gate: response from peer %q rejected: %v", peerName, err), http.StatusBadGateway)
		return
	}

	// The response verified: the round trip is complete on this log too.
	g.log(audit.EventA2ACallReceived, map[string]any{
		"direction":   "response",
		"peer":        peerName,
		"from_did":    respEnv.From,
		"msg_id":      respEnv.MsgID,
		"in_reply_to": respEnv.InReplyTo,
	})

	// Only the verified body crosses into the sandbox, plus the verified
	// sender as a header — the sandbox never sees the raw envelope.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Constle-A2A-From", respEnv.From)
	w.Write(respEnv.Body)
}

// verifyResponse checks a peer's signed response envelope: valid signature
// (Open), signed by exactly the declared peer, addressed to this agent, and
// bound to the request it answers. Order matters for audit precision.
func (g *Gate) verifyResponse(wire []byte, peer manifest.A2APeer, requestMsgID string) (*Envelope, error) {
	env, err := Open(wire)
	if err != nil {
		return nil, err
	}
	if env.From != peer.DID {
		return nil, &RejectError{ReasonUnknownPeer,
			fmt.Sprintf("response signed by %s, but peer %q is declared as %s", env.From, peer.Name, peer.DID)}
	}
	if env.To != g.signer.DID() {
		return nil, &RejectError{ReasonWrongRecipient,
			fmt.Sprintf("response is addressed to %s, not this agent", env.To)}
	}
	if env.InReplyTo != requestMsgID {
		return nil, &RejectError{ReasonReplay,
			fmt.Sprintf("response answers msg_id %q, expected %q — replayed or misrouted response", env.InReplyTo, requestMsgID)}
	}
	return env, nil
}

// readCapped reads a body up to maxBodyBytes, failing closed above the cap:
// an uninspectable message is never signed, relayed, or verified.
func readCapped(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read body: %v", err)
	}
	if len(data) > maxBodyBytes {
		return nil, fmt.Errorf("body exceeds the %d-byte cap", maxBodyBytes)
	}
	return data, nil
}

// log writes one audit entry attributed to this run. Nil logger (unit
// tests) is a no-op.
func (g *Gate) log(event audit.EventType, details map[string]any) {
	if g.logger == nil {
		return
	}
	g.mu.Lock()
	runID, agentName := g.runID, g.agentName
	g.mu.Unlock()
	g.logger.Log(runID, agentName, event, details)
}
