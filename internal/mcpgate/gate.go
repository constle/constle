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
	"strings"
	"sync"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/spending"
	"github.com/constle/constle/pkg/manifest"
)

// maxBodyBytes caps how much of a POST body the gate reads for inspection.
// Requests above the cap fail closed — an uninspectable call is never forwarded.
const maxBodyBytes = 10 << 20 // 10 MB

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
	// Arguments is the raw params.arguments JSON (may be long; consumers truncate).
	Arguments json.RawMessage
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
		go g.server.Serve(ln)
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
// inspecting POSTed JSON-RPC for gated tools/call requests. Everything that
// cannot be positively attributed to a declared server — wrong token,
// unknown id, uninspectable body — fails closed.
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

	// Rewrite the path so the upstream sees exactly its own endpoint path,
	// plus any sub-path the client appended after the server id.
	r.URL.Path = up.path
	if remainder != "" {
		r.URL.Path = strings.TrimSuffix(up.path, "/") + "/" + remainder
	}

	if r.Method != http.MethodPost {
		// GET (server→client SSE stream) and DELETE (session termination)
		// carry no client tool calls; pass through.
		up.proxy.ServeHTTP(w, r)
		return
	}

	g.servePOST(w, r, up)
}

// servePOST inspects one JSON-RPC POST and applies allowlist + gate policy.
func (g *Gate) servePOST(w http.ResponseWriter, r *http.Request, up *upstream) {
	// A body we cannot inspect is a body we do not forward.
	if enc := r.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		http.Error(w, "constle mcp gate: Content-Encoding not supported", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		http.Error(w, "constle mcp gate: cannot read request body", http.StatusBadRequest)
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

	req := Request{
		RunID:          runID,
		AgentName:      agentName,
		ServerID:       up.id,
		Tool:           tool,
		Arguments:      msg.Params.Arguments,
		TimeoutSeconds: timeout,
		OnTimeout:      g.gates.OnTimeout,
	}

	g.log(audit.EventGateTriggered, map[string]any{
		"server":          up.id,
		"tool":            tool,
		"timeout_seconds": timeout,
		"on_timeout":      g.gates.OnTimeout,
	})

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
	if g.approver != nil {
		decision = g.approver.Decide(ctx, req)
	} else {
		<-ctx.Done()
	}
	waitMS := time.Since(start).Milliseconds()

	switch decision {
	case DecisionApproved:
		g.log(audit.EventGateApproved, map[string]any{
			"server": up.id, "tool": tool, "decided_by": "terminal", "wait_ms": waitMS,
		})
		forward()

	case DecisionDenied:
		g.log(audit.EventGateDenied, map[string]any{
			"server": up.id, "tool": tool, "decided_by": "terminal", "wait_ms": waitMS,
		})
		writeJSONRPCError(w, msg.ID, fmt.Sprintf(
			"constle: human gate DENIED tool call %q on server %q", tool, up.id))

	default: // timeout
		g.log(audit.EventGateTimeout, map[string]any{
			"server": up.id, "tool": tool, "on_timeout": g.gates.OnTimeout, "wait_ms": waitMS,
		})
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
func (g *Gate) log(event audit.EventType, details map[string]any) {
	if g.logger == nil {
		return
	}
	g.mu.Lock()
	runID, agentName := g.runID, g.agentName
	g.mu.Unlock()
	g.logger.Log(runID, agentName, event, details)
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
	json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error": map[string]any{
			"code":    -32001,
			"message": message,
		},
	})
}
