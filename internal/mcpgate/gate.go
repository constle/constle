// Package mcpgate implements the human-gate enforcement proxy for MCP.
//
// ============================================================
// mcpgate — protocol-aware chokepoint for MCP tool calls
//
// Squid is the mandatory chokepoint for HTTP egress, but it cannot see
// MCP-level semantics (JSON-RPC methods and tool names inside the stream).
// The gate proxy is the MCP-level equivalent: every declared MCP server is
// reachable from the sandbox ONLY through this proxy, which inspects each
// tools/call request and pauses gated tools for human approval.
//
// MAPPING CONTRACT: a human_gates.require_approval_for entry gates a tool
// call when it is an exact, case-sensitive match for the tool name (the
// params.name of a tools/call request) on any declared server. The tool
// name is the only protocol-level identifier this proxy observes; exact
// match is the only deterministic, auditable mapping. Entries that match
// no declared tool are surfaced as unenforced by the CLI — never silently
// assumed to be covered.
//
// Placement per backend (the proxy itself runs inside the constle process,
// which owns the operator's terminal for the approve/deny prompt):
//
//	Docker:      agent → Squid (existing chokepoint; per-run ACL allows
//	             exactly host.docker.internal:<gate port>) → gate → real MCP
//	Firecracker: agent → TAP gateway:<gate port> (extra per-run nftables
//	             accept, same pattern as the Squid port) → gate → real MCP
//
// The sandbox only ever sees the proxy address; the real MCP URL never
// enters it, and the network policy blocks every direct path. Killing the
// proxy therefore fails closed: the agent's calls get connection errors,
// they cannot fall through to the real server.
// ============================================================
package mcpgate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/humangate"
	"github.com/constle/constle/internal/spending"
	"github.com/constle/constle/pkg/manifest"
)

// maxBodyBytes caps how much of a request body the gate reads for inspection.
// Requests above the cap fail closed — an uninspectable call is never forwarded.
const maxBodyBytes = 10 << 20 // 10 MB

// allowedMethods is the Allow header the gate answers a rejected method with,
// and the set ServeHTTP admits: the three methods Streamable HTTP defines on
// the MCP endpoint. Spelled in the header's canonical order, matching what the
// reference MCP server implementations advertise.
const allowedMethods = "GET, POST, DELETE"

// Decision is the outcome of a human approval request.
type Decision int

const (
	// DecisionNone means no decision arrived (context expired). The gate
	// applies on_timeout.
	DecisionNone Decision = iota
	DecisionApproved
	DecisionDenied
)

// Request describes one gated tool call, passed to the Approver and the Notifier.
type Request struct {
	RunID     string
	AgentName string
	ServerID  string
	Tool      string
	// Arguments is the raw params.arguments JSON, as parsed out of the body
	// that will be forwarded verbatim on approval. An approver that shows a
	// human less than all of it is collecting consent for a call that is not
	// the one that runs, so every consumer must present it whole or refuse.
	//
	// It is what the gate INSPECTED, which is not quite the same as what the
	// upstream will act on: parseJSONRPC resolves a body with a duplicated
	// params or arguments key last-wins, while forward() replays the original
	// bytes, so an upstream that resolves duplicates differently can see
	// something else. That divergence predates this field and is tracked
	// separately; it is noted here so the comment above is not read as a
	// guarantee it cannot give.
	Arguments json.RawMessage

	// SubjectDigest is spec/human-gates-webhook.md §5's digest over Tool and
	// Arguments — the short string that names which call this gate is about,
	// shown on the prompt and recorded on every terminal gate event so an
	// approval is reconstructible later. It commits to the CANONICAL form of
	// the arguments (§5), not to the raw bytes forwarded, so two bodies that
	// canonicalize alike share a digest. Empty only if it could not be
	// computed, which a parsed tools/call cannot produce.
	SubjectDigest string
	// TimeoutSeconds is how long the gate waits before applying OnTimeout.
	TimeoutSeconds int
	// OnTimeout is the manifest's on_timeout policy ("abort" or "proceed").
	OnTimeout string
}

// Approver collects a human decision for a gated call. Implementations must
// return promptly (with DecisionNone) once ctx is done.
type Approver interface {
	Decide(ctx context.Context, req Request) Decision
}

// Outcome is a decision plus enough context for runGate to log it correctly.
// Decision is what determines whether the call proceeds; DecidedBy and Event
// only affect the audit trail.
type Outcome struct {
	Decision Decision

	// DecidedBy names the source that produced Decision, for the audit
	// log's decided_by field (e.g. "webhook"). Empty means the caller's own
	// default ("terminal").
	DecidedBy string

	// Event, when non-empty, overrides the generic
	// EventGateApproved/EventGateDenied event runGate would otherwise log
	// for this Decision — e.g. audit.EventGateSignatureInvalid for a denial
	// caused by a signature that failed to verify, rather than an ordinary
	// human "no".
	Event audit.EventType
}

// ReasoningApprover is implemented by an Approver that can explain a denial
// with a specific audit event instead of the plain deny every Approver can
// produce. TerminalApprover does not implement it; runGate falls back to
// its existing generic logging for any Approver that doesn't.
type ReasoningApprover interface {
	Approver
	DecideWithReason(ctx context.Context, req Request) Outcome
}

// Notifier delivers gate-trigger notifications (e.g. a webhook POST).
type Notifier interface {
	NotifyTriggered(req Request)
}

// Gate is the per-run MCP gate proxy. Create with New, bind with Bind, and
// close with Close. Safe for concurrent use once bound.
type Gate struct {
	servers  map[string]*upstream
	gates    manifest.HumanGates
	gated    map[string]bool // exact tool-name match set
	approver Approver
	notifier Notifier
	logger   *audit.Logger

	// tracker enforces the manifest's spending limits against cost metered
	// from priced servers' responses. Nil when no spending enforcement is
	// active for this run.
	tracker *spending.Tracker

	mu        sync.Mutex
	runID     string
	agentName string
	abortRun  func() // set by SetAbortRun after the sandbox starts
	spendKill func() // set by SetSpendKill after the sandbox starts

	token     string
	port      int
	listeners []net.Listener
	server    *http.Server

	// timeoutOverride shortens the approval timeout in tests (0 = use the
	// manifest's approval_timeout_seconds).
	timeoutOverride time.Duration
}

// upstream is one declared MCP server plus its reverse proxy.
type upstream struct {
	id    string
	path  string          // the endpoint path of the server URL (e.g. /mcp)
	tools map[string]bool // empty = every tool allowed
	// meters is the compiled pricing block; non-empty means every
	// tools/call response of this server is metered (server-wide pricing).
	meters []spending.Meter
	proxy  *httputil.ReverseProxy
}

// New builds a Gate from the manifest's MCP servers, human_gates policy,
// and pricing blocks. tracker may be nil when the run has no spending
// enforcement (no limits declared, or no priced servers to meter them).
func New(m *manifest.AgentManifest, approver Approver, notifier Notifier, logger *audit.Logger, tracker *spending.Tracker) (*Gate, error) {
	g := &Gate{
		servers:   map[string]*upstream{},
		gates:     m.HumanGates,
		gated:     map[string]bool{},
		approver:  approver,
		notifier:  notifier,
		logger:    logger,
		tracker:   tracker,
		agentName: m.Identity.Name,
	}

	if m.HumanGates.Enabled {
		for _, entry := range m.HumanGates.RequireApprovalFor {
			g.gated[entry] = true
		}
	}

	for _, srv := range m.MCP.Servers {
		target, err := url.Parse(srv.URL)
		if err != nil {
			return nil, fmt.Errorf("mcp server %q: invalid url: %w", srv.ID, err)
		}

		tools := map[string]bool{}
		for _, tool := range srv.Tools {
			tools[tool] = true
		}

		var meters []spending.Meter
		if srv.Pricing != nil {
			if tracker == nil {
				return nil, fmt.Errorf("mcp server %q declares pricing but the gate has no spending tracker — refusing to run a priced server unmetered", srv.ID)
			}
			for i, pm := range srv.Pricing.Meters {
				path, err := spending.ParsePath(pm.UsagePath)
				if err != nil {
					return nil, fmt.Errorf("mcp server %q pricing meter %d: %w", srv.ID, i, err)
				}
				price, err := spending.ParseUSD(pm.USDPerUnit)
				if err != nil {
					return nil, fmt.Errorf("mcp server %q pricing meter %d: %w", srv.ID, i, err)
				}
				meters = append(meters, spending.Meter{Path: path, Price: price})
			}
		}

		// Custom Director instead of NewSingleHostReverseProxy: ServeHTTP has
		// already computed the exact upstream path (the default path-joining
		// would turn the endpoint /mcp into /mcp/ and 404 on strict routers),
		// and the Host header must name the upstream, not the gate.
		proxy := &httputil.ReverseProxy{
			// SSE responses (streamable HTTP) must reach the agent unbuffered.
			FlushInterval: -1,
			Director: func(req *http.Request) {
				req.URL.Scheme = target.Scheme
				req.URL.Host = target.Host
				req.Host = target.Host
			},
		}
		if len(meters) > 0 {
			proxy.ModifyResponse = meterResponse
		}

		g.servers[srv.ID] = &upstream{id: srv.ID, path: target.Path, tools: tools, meters: meters, proxy: proxy}
	}

	return g, nil
}

// Bind starts the gate's HTTP listener on every candidate IP that exists on
// this host, all on the same (ephemeral) port, and returns that port plus
// the per-run URL token. At least one candidate must bind.
//
// Multiple candidates exist because of Docker host-networking variance: on
// native Linux the agent's route to the gate terminates on a bridge gateway
// IP; under Docker Desktop it terminates on the WSL loopback via the
// host.docker.internal relay. Binding whichever candidates exist keeps one
// advertised URL working in both layouts.
//
// runID attributes audit entries; it is known to the backend before the
// agent starts, so no gated call can arrive unattributed.
func (g *Gate) Bind(runID string, candidateIPs []string) (port int, token string, err error) {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return 0, "", fmt.Errorf("cannot generate gate token: %w", err)
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
			// Candidate IP not present on this host (or port taken on it) —
			// expected for the layout we are not running under.
			continue
		}
		listeners = append(listeners, ln)
		if port == 0 {
			port = ln.Addr().(*net.TCPAddr).Port
		}
	}
	if len(listeners) == 0 {
		return 0, "", fmt.Errorf("cannot bind MCP gate on any of %v", candidateIPs)
	}

	g.port = port
	g.listeners = listeners
	g.server = &http.Server{Handler: g}
	for _, ln := range listeners {
		go func() {
			// Serve never returns nil. ErrServerClosed is the ordinary exit
			// (Close, at the end of the run); anything else means this
			// listener died on its own. The gate fails closed either way —
			// the agent's MCP calls start erroring — so the value of the
			// error is telling the operator why, instead of leaving them to
			// debug an agent that suddenly cannot reach a declared server.
			if err := g.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintf(os.Stderr, "constle: MCP gate listener on %s stopped: %v\n", ln.Addr(), err)
			}
		}()
	}

	return port, g.token, nil
}

// SetAbortRun installs the callback that terminates the run when a gate
// times out under on_timeout: abort. Installed by the CLI right after the
// sandbox starts; the gate reads it when a timeout actually fires (at
// least approval_timeout_seconds after the sandbox came up), so a gated
// call racing ahead of Start()'s return still aborts correctly. In the
// pathological case of a timeout firing before installation, the gated
// call still fails closed — only the run-wide kill is skipped.
func (g *Gate) SetAbortRun(abort func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.abortRun = abort
}

// Port returns the bound gate port (0 before Bind).
func (g *Gate) Port() int { return g.port }

// Close immediately shuts the gate down, aborting in-flight connections.
// Safe to call before Bind and more than once.
func (g *Gate) Close() error {
	if g.server == nil {
		return nil
	}
	return g.server.Close()
}

// ServeHTTP routes /{token}/servers/{id}[/...] to the matching upstream,
// inspecting JSON-RPC for gated tools/call requests. Everything that cannot be
// positively attributed to a declared server and a method of the MCP transport
// — wrong token, unknown id, undefined method, uninspectable body — fails
// closed.
//
// Inspection is not conditioned on the HTTP method. A JSON-RPC tools/call is
// the same request whether it is POSTed or attached to a GET, and an upstream
// that routes on path alone will run it either way, so a method-shaped hole
// here is a hole in the allowlist, the human gate, the spending meter and the
// audit trail at once.
//
// KNOWN GAPS, in this handler, neither closed by the method allowlist:
// the sub-path after the server id is forwarded without normalising dot
// segments, so a client can address paths on the upstream origin other than
// the declared endpoint; and a request carrying Connection: Upgrade is
// forwarded on an admitted method like any other, so an upstream that answers
// 101 leaves the gate splicing a raw tunnel it cannot inspect. Both predate
// the method allowlist and both are tracked separately — the guarantee this
// handler makes is over the JSON-RPC a request carries, not yet over every
// byte it can move.
func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/"+g.token+"/servers/")
	if !ok {
		http.Error(w, "constle mcp gate: unknown path", http.StatusNotFound)
		return
	}
	serverID, remainder, _ := strings.Cut(rest, "/")
	up, ok := g.servers[serverID]
	if !ok {
		http.Error(w, "constle mcp gate: undeclared MCP server", http.StatusForbidden)
		return
	}

	// A tripped spending tracker rejects EVERYTHING, all methods, all
	// servers: the run is being killed, and until the kill lands the agent
	// must not be able to complete another call. Re-firing the kill here
	// closes the startup race where a violation beat SetSpendKill.
	if g.tracker != nil && g.tracker.Tripped() != spending.ViolationNone {
		g.fireSpendKill()
		http.Error(w, fmt.Sprintf(
			"constle: spending limit reached (%s) — run is being terminated", g.tracker.Tripped()),
			http.StatusForbidden)
		return
	}

	// Method allowlist. Streamable HTTP — the only MCP transport Constle
	// supports — defines exactly three methods on the endpoint: POST carries
	// every JSON-RPC message, GET opens the server→client SSE stream, DELETE
	// terminates the session. Nothing else is an MCP operation, so nothing
	// else is forwarded: a method outside the set is refused here rather than
	// proxied, because the gate cannot enforce a policy on a request whose
	// protocol it does not model.
	//
	// The comparison must stay exact and case-sensitive (RFC 9110 §9.1: "the
	// method token is case-sensitive"). net/http admits any valid token as a
	// method, so a lowercase "post" is a different method than POST — folding
	// case here would hand it the POST path's parse and re-open the bypass
	// from the other side.
	//
	// 405 rather than this repo's usual fail-closed 404 (internal/a2a/gate.go)
	// because the client is an MCP client and MCP gives both codes meanings:
	// 405 is what the transport itself prescribes for a method the endpoint
	// does not serve, and what both reference SDKs answer, while 404 means
	// "this session was terminated" — on which a conforming client starts a
	// new session, turning a refusal into a reconnect loop. RFC 9110 §15.5.6
	// requires the Allow header on a 405.
	switch r.Method {
	case http.MethodPost, http.MethodGet, http.MethodDelete:
	default:
		g.log(audit.EventMCPRequestBlocked, map[string]any{
			"server": up.id,
			"method": clampMethod(r.Method),
			"reason": "method not defined by the MCP transport",
		})
		w.Header().Set("Allow", allowedMethods)
		http.Error(w, "constle mcp gate: "+allowedMethods+" are the only methods the MCP transport defines",
			http.StatusMethodNotAllowed)
		return
	}

	// Rewrite the path so the upstream sees exactly its own endpoint path,
	// plus any sub-path the client appended after the server id.
	r.URL.Path = up.path
	if remainder != "" {
		r.URL.Path = strings.TrimSuffix(up.path, "/") + "/" + remainder
	}

	g.serveInspected(w, r, up)
}

// serveInspected inspects one request — whatever its method — and applies
// allowlist + gate policy before any MCP message reaches the upstream.
//
// Every method the gate forwards arrives here, because the checks below are
// what make the gate a gate: skipping them for a method is skipping the tool
// allowlist, the human gate, spending metering and the tool_call audit
// bracketing all at once, and the JSON-RPC body that selects a tool is
// carried just as well by a GET as by a POST.
//
// The split between methods is therefore not "which ones are inspected" but
// "what a legitimate body looks like for this one": POST carries the
// JSON-RPC message, and GET and DELETE carry no message at all.
func (g *Gate) serveInspected(w http.ResponseWriter, r *http.Request, up *upstream) {
	// A body we cannot inspect is a body we do not forward.
	if enc := r.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		http.Error(w, "constle mcp gate: Content-Encoding not supported", http.StatusUnsupportedMediaType)
		return
	}

	// net/http guarantees a non-nil Body on a server request; the fallback
	// covers a hand-built Request that reaches ServeHTTP directly.
	src := r.Body
	if src == nil {
		src = http.NoBody
	}

	// Only a POST can carry an MCP message, so only a POST needs its body
	// read: on any other method the first byte already settles the question,
	// and stopping there keeps a body the gate is about to refuse from being
	// buffered, and keeps every non-POST refusal on the one audited path
	// below rather than splitting it across the size cap.
	//
	// The decision has to come from bytes actually read, never from
	// ContentLength: a chunked request declares no length (ContentLength -1),
	// so a length-based test reads "no body" on exactly the framing an
	// attacker controls.
	limit := int64(maxBodyBytes) + 1
	if r.Method != http.MethodPost {
		limit = 1
	}
	body, err := io.ReadAll(io.LimitReader(src, limit))
	if err != nil {
		http.Error(w, "constle mcp gate: cannot read request body", http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodPost {
		// GET and DELETE, the two non-POST methods the transport defines,
		// carry no JSON-RPC message in any revision of it: "Every JSON-RPC
		// message sent from the client MUST be a new HTTP POST request to the
		// MCP endpoint." GET opens the server→client stream and DELETE names
		// its session in a header, so for both of them a legitimate body is
		// an absent one, and that is all there is to inspect in the JSON-RPC
		// a request of theirs can carry. (It is not all a request can carry —
		// see the KNOWN GAPS on ServeHTTP.)
		//
		// A body on one of them is refused rather than run through the gate
		// below. It cannot have come from a conforming client, and gating it
		// would be worse than refusing it: many servers ignore a GET body
		// entirely, so the gate would prompt a human, bracket the call in the
		// signed audit log, and meter the response — all for a tool call the
		// upstream never ran, letting a sandboxed agent write fiction into
		// the log and the spending ledger.
		if len(body) > 0 {
			g.log(audit.EventMCPRequestBlocked, map[string]any{
				"server": up.id,
				"method": clampMethod(r.Method),
				"reason": "body on a method that carries no MCP message",
			})
			http.Error(w, fmt.Sprintf(
				"constle mcp gate: %s carries no MCP message — a JSON-RPC body must be POSTed so the gate can inspect it",
				clampMethod(r.Method)), http.StatusBadRequest)
			return
		}
		// The body has been consumed to prove it was empty, so hand the proxy
		// an explicitly empty one. http.NoBody with ContentLength 0 makes
		// ReverseProxy send no body framing at all, which is what a bodiless
		// GET looked like before it was read — a chunked empty body would
		// otherwise be re-emitted as a lone terminating chunk that strict SSE
		// endpoints reject.
		r.Body, r.ContentLength, r.TransferEncoding = http.NoBody, 0, nil
		up.proxy.ServeHTTP(w, r)
		return
	}

	if len(body) > maxBodyBytes {
		http.Error(w, "constle mcp gate: request body too large to inspect", http.StatusRequestEntityTooLarge)
		return
	}

	msg, jsonErr := parseJSONRPC(body)
	if jsonErr != nil {
		http.Error(w, "constle mcp gate: "+jsonErr.Error(), http.StatusBadRequest)
		return
	}

	forward := func() {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		up.proxy.ServeHTTP(w, r)
	}

	if msg.Method != "tools/call" {
		forward()
		return
	}

	tool := msg.Params.Name

	// Priced server: attach the metering job so this tools/call's response
	// is captured and charged by the upstream's ModifyResponse hook.
	if len(up.meters) > 0 {
		job := &meterJob{gate: g, up: up, tool: tool, reqID: msg.ID}
		r = r.WithContext(context.WithValue(r.Context(), meterCtxKey{}, job))
	}

	// From here on, forwarding a tools/call also records it: tool_call_start
	// when the call is handed to the upstream, tool_call_end when the proxied
	// response has been fully written back. Bracketing the forward (rather
	// than the arrival) keeps exactly one meaning — "this call reached the
	// upstream" — so blocked, denied, and timed-out-under-abort calls, which
	// have their own terminal events, never emit a start with no upstream
	// behind it. rpc_id ties the pair together when concurrent calls to the
	// same tool interleave in the log; argument bytes are counted, not
	// copied — tool arguments routinely carry secrets and payloads that do
	// not belong in an audit log.
	rpcID := compactRPCID(msg.ID)
	forward = func() {
		startDetails := map[string]any{
			"server":     up.id,
			"tool":       tool,
			"args_bytes": len(msg.Params.Arguments),
		}
		if rpcID != "" {
			startDetails["rpc_id"] = rpcID
		}
		g.log(audit.EventToolCallStart, startDetails)

		rec := &statusRecorder{ResponseWriter: w}
		began := time.Now()
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		up.proxy.ServeHTTP(rec, r)

		endDetails := map[string]any{
			"server":      up.id,
			"tool":        tool,
			"duration_ms": time.Since(began).Milliseconds(),
			"http_status": rec.status(),
		}
		if rpcID != "" {
			endDetails["rpc_id"] = rpcID
		}
		g.log(audit.EventToolCallEnd, endDetails)
	}

	// Manifest tool allowlist: undeclared tools are rejected outright, no gate.
	if len(up.tools) > 0 && !up.tools[tool] {
		g.log(audit.EventMCPToolBlocked, map[string]any{
			"server": up.id,
			"tool":   tool,
			"reason": "not in declared tools list",
		})
		writeJSONRPCError(w, msg.ID, fmt.Sprintf(
			"constle: tool %q is not declared for MCP server %q in the Agentfile", tool, up.id))
		return
	}

	if !g.gated[tool] {
		forward()
		return
	}

	g.runGate(w, msg, up, tool, forward)
}

// runGate blocks a gated tools/call until a human decision or timeout, then
// enforces the outcome. Exactly one terminal audit event is written per gate.
func (g *Gate) runGate(w http.ResponseWriter, msg *jsonRPCMessage, up *upstream, tool string, forward func()) {
	g.mu.Lock()
	runID, agentName := g.runID, g.agentName
	g.mu.Unlock()

	timeout := g.gates.ApprovalTimeoutSeconds
	if timeout <= 0 {
		timeout = 300
	}

	// Every terminal event below carries this digest, which is what makes an
	// approval reconstructible after the fact: gate_approved alone says that
	// something was approved, not what — and the arguments themselves must
	// never be copied into the audit log, since they routinely carry secrets
	// and payloads.
	//
	// That privacy property is real but partial, and worth stating rather
	// than implying: the digest is an UNSALTED SHA-256 over the tool name and
	// arguments (spec §5 requires exactly that, so it cannot be salted
	// without breaking the cross-side reproducibility it exists for). Over an
	// enumerable argument space — a PIN, a boolean confirmation, an address
	// from a known set — it is recoverable by brute force in milliseconds.
	// The audit log is designed to travel, so treat this as a forensic
	// handle, not a confidentiality boundary: assume anyone who can read the
	// log can learn guessable arguments.
	//
	// SubjectDigest returns "" on the errors it can raise, and none of them
	// is reachable for a body parseJSONRPC already unmarshalled. A missing
	// digest degrades to "no digest recorded" rather than blocking the call:
	// this value is evidence about the gate's decision, never an input to it.
	//
	// WebhookApprover deliberately recomputes its own copy rather than taking
	// this one (webhook_approver.go). They agree by construction — one pure
	// function, one set of inputs, the empty-arguments default living inside
	// SubjectDigest itself — and the duplication is what keeps that approver
	// safe to use with a Request built anywhere: consuming a caller-supplied
	// digest would let an empty one through, and "" == "" verifies.
	subjectDigest, _ := humangate.SubjectDigest(tool, msg.Params.Arguments)

	req := Request{
		RunID:          runID,
		AgentName:      agentName,
		ServerID:       up.id,
		Tool:           tool,
		Arguments:      msg.Params.Arguments,
		SubjectDigest:  subjectDigest,
		TimeoutSeconds: timeout,
		OnTimeout:      g.gates.OnTimeout,
	}

	// gateDetails seeds the details map every terminal event of this gate
	// shares, so none of them can drift out of naming the same subject.
	gateDetails := func(extra map[string]any) map[string]any {
		d := map[string]any{"server": up.id, "tool": tool}
		if subjectDigest != "" {
			d["subject_digest"] = subjectDigest
		}
		for k, v := range extra {
			d[k] = v
		}
		return d
	}

	g.log(audit.EventGateTriggered, gateDetails(map[string]any{
		"timeout_seconds": timeout,
		"on_timeout":      g.gates.OnTimeout,
	}))

	if g.notifier != nil {
		g.notifier.NotifyTriggered(req)
	}

	timeoutDur := time.Duration(timeout) * time.Second
	if g.timeoutOverride > 0 {
		timeoutDur = g.timeoutOverride
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDur)
	defer cancel()

	decision := DecisionNone
	decidedBy := "terminal"
	var eventOverride audit.EventType
	if ra, ok := g.approver.(ReasoningApprover); ok {
		outcome := ra.DecideWithReason(ctx, req)
		decision, eventOverride = outcome.Decision, outcome.Event
		if outcome.DecidedBy != "" {
			decidedBy = outcome.DecidedBy
		}
	} else if g.approver != nil {
		decision = g.approver.Decide(ctx, req)
	} else {
		<-ctx.Done()
	}
	waitMS := time.Since(start).Milliseconds()

	switch decision {
	case DecisionApproved:
		event := audit.EventGateApproved
		if eventOverride != "" {
			event = eventOverride
		}
		g.log(event, gateDetails(map[string]any{"decided_by": decidedBy, "wait_ms": waitMS}))
		forward()

	case DecisionDenied:
		event := audit.EventGateDenied
		if eventOverride != "" {
			event = eventOverride
		}
		g.log(event, gateDetails(map[string]any{"decided_by": decidedBy, "wait_ms": waitMS}))
		writeJSONRPCError(w, msg.ID, fmt.Sprintf(
			"constle: human gate DENIED tool call %q on server %q", tool, up.id))

	default: // timeout
		g.log(audit.EventGateTimeout, gateDetails(map[string]any{
			"on_timeout": g.gates.OnTimeout, "wait_ms": waitMS,
		}))
		if g.gates.OnTimeout == "proceed" {
			forward()
			return
		}
		// abort (the default): fail the call, then terminate the run.
		writeJSONRPCError(w, msg.ID, fmt.Sprintf(
			"constle: human gate for tool %q timed out after %ds — aborting run (on_timeout: abort)",
			tool, timeout))
		// Read the abort callback NOW, not at gate entry: a fast agent can
		// fire its first gated call before the backend's Start() has even
		// returned to the CLI (observed on Docker Desktop), i.e. before
		// SetAbortRun ran. By the time the timeout fires, whole seconds
		// later, the callback is reliably installed.
		g.mu.Lock()
		abortRun := g.abortRun
		g.mu.Unlock()
		if abortRun != nil {
			abortRun()
		}
	}
}

// log writes one audit entry attributed to this run. Nil logger (unit tests)
// is a no-op.
//
// Every event that reaches here is a decision the gate has already made and
// acted on — a call blocked, approved, denied, or timed out. The write is
// therefore deliberately NOT allowed to change that outcome: refusing an
// already-approved call because the record of it could not be written would
// make an unwritable disk a second, undeclared enforcement policy. What must
// not happen is the loss going unnoticed, so a failure is announced at once
// and the CLI refuses to report the run as cleanly audited (Logger.Err).
func (g *Gate) log(event audit.EventType, details map[string]any) {
	if g.logger == nil {
		return
	}
	g.mu.Lock()
	runID, agentName := g.runID, g.agentName
	g.mu.Unlock()
	if err := g.logger.Log(runID, agentName, event, details); err != nil {
		audit.WarnWriteFailure(event, err)
	}
}

// outf writes one piece of operator-facing text — an approval prompt, a
// webhook warning — to a caller-supplied writer.
//
// The dropped error is justified once here rather than at a dozen call
// sites: this writer IS the channel constle reports problems on, so a
// failure to write to it has nowhere left to be reported. Nothing the gate
// enforces depends on it either — a gated call is decided and audited
// whether or not the human ever saw the prompt.
func outf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// statusRecorder captures the HTTP status a proxied response was sent with,
// for the tool_call_end audit event. It must stay transparent to streaming:
// Flush passes through (SSE responses are proxied with FlushInterval -1) and
// Unwrap lets http.ResponseController reach every other optional interface of
// the underlying writer.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.code == 0 {
		s.code = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK // implicit 200 on first Write
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// status returns the recorded status, or 0 when nothing was ever written —
// which for a proxied call means the upstream connection failed before any
// response reached the agent.
func (s *statusRecorder) status() int { return s.code }

// clampMethod bounds a request method before it is logged or echoed. net/http
// already rejects anything that is not a valid HTTP token, so the value is
// safe to render; the cap keeps a long one from bloating an audit line, the
// same principle as compactRPCID.
func clampMethod(method string) string {
	const maxMethodLen = 32
	if len(method) > maxMethodLen {
		return method[:maxMethodLen]
	}
	return method
}

// compactRPCID renders a JSON-RPC id for audit details: the raw JSON token
// (`1`, `"abc"`), capped so a hostile id cannot bloat the log, and empty for
// notifications, which have no id.
func compactRPCID(id json.RawMessage) string {
	const maxIDLen = 64
	s := string(id)
	if len(s) > maxIDLen {
		s = s[:maxIDLen]
	}
	return s
}

// jsonRPCMessage is the subset of a JSON-RPC request the gate inspects.
type jsonRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

// parseJSONRPC parses a single JSON-RPC message, failing closed on batches:
// a batch could smuggle a gated tools/call past a naive object parse.
func parseJSONRPC(body []byte) (*jsonRPCMessage, error) {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, errors.New("empty JSON-RPC body")
	}
	if trimmed[0] == '[' {
		return nil, errors.New("JSON-RPC batch requests are not supported through the gate proxy")
	}

	var msg jsonRPCMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC body: %v", err)
	}
	return &msg, nil
}

// writeJSONRPCError responds with a JSON-RPC error object (code -32001,
// implementation-defined server error) so MCP clients see a protocol-level
// failure rather than a broken connection.
func writeJSONRPCError(w http.ResponseWriter, id json.RawMessage, message string) {
	if len(id) == 0 {
		// tools/call as a notification has no id to respond to; an HTTP
		// error is the only signal available.
		http.Error(w, message, http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// A failed encode means the agent's connection is already gone, which is
	// itself a denial of the call — the outcome this function exists to
	// produce. There is no second channel to report it on and nothing to
	// retry, so the error is dropped.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error": map[string]any{
			"code":    -32001,
			"message": message,
		},
	})
}
