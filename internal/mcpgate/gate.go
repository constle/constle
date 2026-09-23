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
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/humangate"
	"github.com/constle/constle/internal/spending"
	"github.com/constle/constle/internal/termsafe"
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

// methodToolsCall is the one JSON-RPC method the gate inspects. The
// comparison against it is exact and case-sensitive, and parseJSONRPC refuses
// the near-misses rather than letting one route past inspection.
const methodToolsCall = "tools/call"

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
	// It is what the gate INSPECTED, and that is now the same call the
	// upstream acts on: parseJSONRPC refuses a body whose member names any
	// two conforming parsers could resolve differently — a repeated key, or
	// one that differs from another only in case — at every depth, arguments
	// included, so these bytes cannot be read one way here and another way
	// upstream. What the gate cannot promise is how the TOOL then reads a
	// value it was handed unambiguously.
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

	// Evidence, when non-nil, is the signed decision this Outcome came from,
	// which runGate writes to the audit log so the decision can be
	// re-verified offline against the approver's key
	// (spec/human-gates-webhook.md §9). An Approver that produces no signed
	// statement — TerminalApprover, whose answer is a keystroke — leaves it
	// nil, and the entry keeps exactly the details it always had.
	//
	// It is evidence ABOUT a decision, never an input TO one, on the same
	// rule the subject_digest already follows in runGate: nothing here may
	// change whether the call proceeds. Decision alone decides that, and
	// Evidence that could not be built or written must not turn an approval
	// into a denial.
	Evidence *humangate.RecordedDecision
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

	// The master switch, read through the one predicate the CLI also reports
	// from, so neither side can start disagreeing about whether gates are on
	// at all (manifest.HumanGates.GatesArmed).
	//
	// The entry set built below is deliberately wider than what the CLI calls
	// enforced: an entry no declared server could serve stays here so the
	// case-fold near-miss refusal further down still covers it, while
	// EnforcedGateEntries drops it rather than promise a gate on a tool the
	// tools allowlist rejects first.
	if m.HumanGates.GatesArmed() {
		for _, entry := range m.HumanGates.RequireApprovalFor {
			g.gated[entry] = true
		}
	}

	for _, srv := range m.MCP.Servers {
		target, err := url.Parse(srv.URL)
		if err != nil {
			return nil, fmt.Errorf("mcp server %q: invalid url: %w", srv.ID, err)
		}

		// The endpoint path is the base every forwarded request is held to, so
		// it has to be unambiguous itself. A declared ".../safe/.." would pass
		// withinEndpoint for "/safe/../admin" while an origin that normalises
		// serves "/admin": the gate's promise would hold for the string and
		// fail for the resource. Refused here rather than in the parser
		// because this is where the base is taken, so no caller can reach the
		// rewrite with a base that was never checked. The endpoint's check
		// admits '@' and ':' where the sub-path's does not; see
		// ambiguousEndpointReason for why that is safe only here.
		if reason := ambiguousEndpointReason(strings.TrimPrefix(target.Path, "/")); reason != "" {
			return nil, fmt.Errorf(
				"mcp server %q: url path %q cannot be an endpoint — %s; "+
					"declare the endpoint the server actually serves",
				srv.ID, target.Path, reason)
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
				scrubHopByHop(req.Header)
			},
			ModifyResponse: refuseProtocolSwitch(len(meters) > 0),
			// ErrorLog rather than ErrorHandler: ReverseProxy routes every
			// message it emits through this logger, the default error
			// handler's included, so one writer covers the lot and the 502
			// that handler sends stays exactly as it was.
			ErrorLog: log.New(gateLogWriter{"proxy"}, "", 0),
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
	// The same omission one level up: an http.Server with no ErrorLog logs
	// through the global logger too, and what it logs — a handler panic, a
	// TLS handshake failure — is assembled from whatever the peer sent.
	g.server = &http.Server{Handler: g, ErrorLog: log.New(gateLogWriter{"server"}, "", 0)}
	for _, ln := range listeners {
		go func() {
			// Serve never returns nil. ErrServerClosed is the ordinary exit
			// (Close, at the end of the run); anything else means this
			// listener died on its own. The gate fails closed either way —
			// the agent's MCP calls start erroring — so the value of the
			// error is telling the operator why, instead of leaving them to
			// debug an agent that suddenly cannot reach a declared server.
			if err := g.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				termsafe.Fprintf(os.Stderr, "constle: MCP gate listener on %s stopped: %v\n", ln.Addr(), err)
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
// Two further rules hold the request to the shape the gate can make a promise
// about. The target must address the declared endpoint or a path under it, and
// a sub-path that some second reading of the same bytes would turn into
// structure — a dot segment, an interior empty segment, a percent sign that
// survives one decode, a path parameter, a backslash, or any byte outside the
// RFC 3986 unreserved set, where the NFKC and best-fit readings live — is
// refused rather than normalised, because normalising it would silently pick
// one of the readings.
// And a request asking to stop speaking HTTP (Connection: Upgrade) is refused,
// with an upstream's 101 refused in turn, so no tunnel is ever spliced through
// the gate. The guarantee is over every byte a request can move, not only over
// the JSON-RPC it carries.
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

	// The sub-path is forwarded, so it decides which resource on the origin
	// this request reaches. A segment either side would resolve — "..", an
	// interior empty segment, or a separator or dot hidden behind
	// percent-encoding or behind a Unicode form the origin folds into one —
	// lets a client address a path other than the declared endpoint: another
	// MCP server mounted beside this one, whose tool allowlist was never
	// consulted, or anything else the origin serves.
	//
	// The check runs on the decoded sub-path, which is what r.URL.Path holds:
	// "%2e%2e%2f" has already become "../" by the time it arrives here, and
	// because the rewrite below clears RawPath, it is also what an upstream
	// decodes back out of the wire. Refusing rather than resolving is the rule
	// parseJSONRPC already applies to an ambiguous body: the gate does not
	// forward what it cannot read exactly one way.
	if reason := ambiguousPathReason(remainder); reason != "" {
		g.log(audit.EventMCPRequestBlocked, map[string]any{
			"server": up.id,
			"method": clampMethod(r.Method),
			"reason": reason,
		})
		http.Error(w, "constle mcp gate: "+reason, http.StatusBadRequest)
		return
	}

	// A protocol upgrade asks to stop speaking HTTP. Streamable HTTP defines
	// none — POST carries every message, GET opens the SSE stream, DELETE ends
	// the session — so nothing legitimate is lost by refusing one. Forwarded,
	// an upgrade the upstream accepts turns the reverse proxy into a raw
	// bidirectional splice: the gate would hold open a tunnel it cannot
	// inspect, to a host the sandbox is otherwise forbidden to reach directly
	// at all, since an MCP server's host must not appear in
	// network.allowed_hosts. The Director scrubs the headers as well, so the
	// splice stays unreachable even if this refusal is ever moved or skipped.
	if requestsUpgrade(r.Header) {
		g.log(audit.EventMCPRequestBlocked, map[string]any{
			"server": up.id,
			"method": clampMethod(r.Method),
			"reason": reasonProtocolUpgrade,
		})
		http.Error(w, "constle mcp gate: "+reasonProtocolUpgrade, http.StatusBadRequest)
		return
	}

	// Rewrite the path so the upstream sees exactly its own endpoint path,
	// plus any sub-path the client appended after the server id. RawPath is
	// cleared with it: it still describes the original target, and leaving it
	// in place would let EscapedPath put bytes on the wire that were never the
	// path checked above.
	r.URL.Path = up.path
	if remainder != "" {
		r.URL.Path = strings.TrimSuffix(up.path, "/") + "/" + remainder
	}
	r.URL.RawPath = ""

	// A post-condition on the rewrite, not a check on the client: after the
	// refusals above nothing can reach this line with a path outside the
	// endpoint. It stays because the guarantee belongs to the joining, and a
	// later change to it would otherwise reopen the gap with nothing failing.
	if !withinEndpoint(up.path, r.URL.Path) {
		g.log(audit.EventMCPRequestBlocked, map[string]any{
			"server": up.id,
			"method": clampMethod(r.Method),
			"reason": reasonPathEscapedEndpoint,
		})
		http.Error(w, "constle mcp gate: "+reasonPathEscapedEndpoint, http.StatusBadRequest)
		return
	}

	g.serveInspected(w, r, up)
}

// Refusal reasons for a request the gate will not forward. They are fixed
// strings: each one reaches the audit log and the sandbox, and the offending
// path is attacker-controlled, so naming it in either place would let the
// sender write its own text into the signed log.
const (
	reasonDotSegment          = "dot or empty segment in the request path"
	reasonPercentEncoding     = "percent-encoding in the request path"
	reasonPathParameter       = "path parameter in the request path"
	reasonBackslash           = "backslash in the request path"
	reasonUnlistedCharacter   = "character outside A-Z a-z 0-9 - . _ ~ in the request path"
	reasonProtocolUpgrade     = "the MCP transport defines no protocol upgrade"
	reasonPathEscapedEndpoint = "forwarded path outside the declared endpoint"
)

// ambiguousPathReason reports why a sub-path cannot be forwarded, or "" when
// it can.
//
// It judges the decoded sub-path, which is the form the gate reads and — since
// the rewrite clears RawPath and lets Go re-escape from it — also the form an
// upstream gets back after decoding the wire once. Everything refused here is
// a segment that some second reading of the same bytes turns into structure:
//
//   - "." and ".." are structure to every reader, and an empty segment is
//     refused when another follows it, because a leading or doubled slash
//     puts "//host" on the wire, which a parser is entitled to read as an
//     authority rather than a path. A trailing empty segment is a path a
//     server may legitimately distinguish, so it stays.
//   - A percent sign in the *decoded* sub-path means the sender encoded a
//     percent sign, and the only thing that reveals is an upstream decoding
//     twice: "%252e%252e%252f" arrives here as "%2e%2e%2f" and becomes "../"
//     on a second pass. Ordinary encoding is unaffected — "report%2Ejson"
//     decodes to "report.json", which holds no percent sign and is forwarded.
//   - A semicolon starts a path parameter, which several servers strip before
//     they normalise, turning "..;" back into "..".
//   - A backslash is not a separator in a URL, but an origin on a platform
//     that treats it as one resolves "..\..\x" exactly like "../../x".
//
// Those name the readings that are known, and they cannot be the whole rule,
// because the readings are open-ended: NFKC folds '．' into '.' and '‥' into
// "..", a Windows best-fit code page maps '∕' to '/' and '¥' to '\', a decoder
// that re-parses the decoded path ends it at '?' or '#' and drops a tab, and
// every further normalisation form or code page is one more table. So every
// byte must also be RFC 3986 unreserved — A-Z a-z 0-9 - . _ ~ — the only
// characters that mean the same whether or not they arrived percent-encoded
// (RFC 3986 §6.2.2.2), and that all four Unicode normalisation forms and
// every Windows ANSI code page leave as they are. The named rules run first
// so that the audit log says which known reading a refusal was; the allowlist
// is what makes the list of readings irrelevant.
//
// Segments are compared whole, so "..foo", "foo..bar" and a name that merely
// contains a dot stay legal; only a segment that *is* a dot segment does not.
func ambiguousPathReason(remainder string) string {
	return pathReason(remainder, unreserved, reasonUnlistedCharacter)
}

// reasonUnlistedEndpointCharacter is ambiguousEndpointReason's counterpart of
// reasonUnlistedCharacter. It names the endpoint's wider set, and it never
// reaches the audit log: an endpoint is refused when the gate is built, before
// there is a request to log.
const reasonUnlistedEndpointCharacter = "character outside A-Z a-z 0-9 - . _ ~ @ : in the endpoint path"

// ambiguousEndpointReason is ambiguousPathReason for the declared endpoint
// path, held to the same rules over a wider set of bytes: '@' and ':' are
// admitted as well, because hosted MCP servers serve paths such as
// "/@org/name/mcp".
//
// The two sets differ on purpose. The endpoint is a constant the operator
// wrote into the Agentfile, checked once when the gate is built; the sub-path
// is chosen by the sender of every request, so it is the part an attacker
// controls, and it gets nothing beyond the unreserved set. Joining cannot mix
// the two: the sub-path follows a separator and can hold neither byte, so no
// request places '@' or ':' anywhere the operator did not.
//
// Neither byte is inert to every reader. '@' is structure only inside an
// authority, and the refusal of a leading empty segment keeps "//" — and with
// it any authority — off the front of the path. ':' after a single letter at
// the start of the path names a drive to a Windows file server that joins
// paths the way Python's ntpath does, so a declared "/C:/x" means something
// other than it says to such an origin. That reading is confined to a string
// the operator wrote.
func ambiguousEndpointReason(endpoint string) string {
	return pathReason(endpoint, endpointByte, reasonUnlistedEndpointCharacter)
}

// pathReason applies the rules ambiguousPathReason describes, with allowed as
// the byte allowlist and unlisted as the reason a byte outside it is refused
// with. Callers are the two functions above, and no other: the allowlist is
// the whole difference between a sub-path and an endpoint, so it is fixed by
// which of them is called rather than passed in at the call site.
func pathReason(p string, allowed func(byte) bool, unlisted string) string {
	segments := strings.Split(p, "/")
	for i, segment := range segments {
		switch {
		case segment == "." || segment == "..":
			return reasonDotSegment
		case segment == "" && i != len(segments)-1:
			return reasonDotSegment
		case strings.Contains(segment, "%"):
			return reasonPercentEncoding
		case strings.Contains(segment, ";"):
			return reasonPathParameter
		case strings.Contains(segment, "\\"):
			return reasonBackslash
		case !allBytes(segment, allowed):
			return unlisted
		}
	}
	return ""
}

// allBytes reports whether allowed holds for every byte of segment. It walks
// bytes, not runes, so the answer never depends on the segment being valid
// UTF-8: an overlong "%C0%AE" is two bytes outside either set, whatever a
// lenient decoder would make of them.
func allBytes(segment string, allowed func(byte) bool) bool {
	for i := 0; i < len(segment); i++ {
		if !allowed(segment[i]) {
			return false
		}
	}
	return true
}

// unreserved reports whether b is an RFC 3986 unreserved character (§2.3).
func unreserved(b byte) bool {
	switch {
	case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9':
		return true
	case b == '-', b == '.', b == '_', b == '~':
		return true
	}
	return false
}

// endpointByte reports whether b may appear in a declared endpoint path: the
// unreserved set, plus the two bytes ambiguousEndpointReason explains.
func endpointByte(b byte) bool {
	return unreserved(b) || b == '@' || b == ':'
}

// withinEndpoint reports whether a forwarded path is the declared endpoint or
// sits beneath it. The comparison is on whole segments: "/mcp-admin" is not
// under "/mcp", where a plain prefix test would say it is.
func withinEndpoint(endpoint, forwarded string) bool {
	endpoint = strings.TrimSuffix(endpoint, "/")
	return forwarded == endpoint || strings.HasPrefix(forwarded, endpoint+"/")
}

// requestsUpgrade reports whether a request asks to switch protocols. Both
// spellings count: the Upgrade header naming a protocol, and the "upgrade"
// token inside Connection, which is what net/http's reverse proxy reads when
// it decides whether to splice a 101 response.
func requestsUpgrade(h http.Header) bool {
	if len(h.Values("Upgrade")) > 0 {
		return true
	}
	return headerHasToken(h, "Connection", "upgrade")
}

// headerHasToken reports whether a comma-separated header carries one token,
// compared case-insensitively as RFC 9110 requires. net/http keeps repeated
// headers as separate values, so every value is scanned.
func headerHasToken(h http.Header, name, token string) bool {
	for _, value := range h.Values(name) {
		for _, candidate := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(candidate), token) {
				return true
			}
		}
	}
	return false
}

// hopByHopHeaders are the connection-scoped headers of RFC 9110 §7.6.1, which
// a proxy consumes rather than forwards. httputil.ReverseProxy strips them
// itself — except that it deliberately restores Connection and Upgrade for an
// upgrade request, which is the splice this gate refuses. scrubHopByHop runs
// in the Director, before the proxy decides whether an upgrade was asked for,
// so with these gone the decision can only be "no".
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// scrubHopByHop removes the connection-scoped headers from an outbound
// request: first the ones the sender named in Connection, as RFC 9110 requires,
// then Connection itself and the rest of the fixed set.
func scrubHopByHop(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, named := range strings.Split(value, ",") {
			if named = strings.TrimSpace(named); named != "" {
				h.Del(named)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
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
		// the path and upgrade rules on ServeHTTP hold the rest.)
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
		// An ambiguous body is audited where a merely malformed one is not:
		// the second is a broken client, the first is an attempt to have the
		// gate inspect a different call than the upstream runs, and that is
		// worth a line in the signed log. The reason is a fixed string — the
		// offending name is attacker-controlled, and it reaches the agent in
		// the HTTP response instead, which is read only by the sender that
		// already has it.
		if errors.Is(jsonErr, errAmbiguousBody) {
			g.log(audit.EventMCPRequestBlocked, map[string]any{
				"server": up.id,
				"method": clampMethod(r.Method),
				"reason": "ambiguous JSON-RPC body",
			})
		}
		http.Error(w, "constle mcp gate: "+jsonErr.Error(), http.StatusBadRequest)
		return
	}

	forward := func() {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		up.proxy.ServeHTTP(w, r)
	}

	if msg.Method != methodToolsCall {
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
		// A name that folds to a gated tool's without matching it is refused
		// rather than forwarded ungated. The package's mapping contract is an
		// exact, case-sensitive match, which is what makes gating auditable —
		// but exactness binds the upstream only if the upstream agrees, and a
		// server that dispatches tool names case-insensitively would run
		// send_email for a call the gate read as SEND_EMAIL and never gated.
		// A declared tools allowlist already blocks the near-miss above as
		// undeclared; this closes the same hole on a server that declares no
		// allowlist, which the manifest permits.
		for gatedTool := range g.gated {
			if !strings.EqualFold(tool, gatedTool) {
				continue
			}
			g.log(audit.EventMCPToolBlocked, map[string]any{
				"server": up.id,
				"tool":   clampJSONValue(tool),
				"reason": "case variant of a gated tool name",
			})
			writeJSONRPCError(w, msg.ID, fmt.Sprintf(
				"constle: tool %q differs from gated tool %q only in case — the gate matches tool names exactly",
				clampJSONValue(tool), gatedTool))
			return
		}
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

	// evidence is the signed decision, once an approver has produced one.
	// It is declared here so gateDetails can pick it up: still nil when
	// gate_triggered is written (no request_id exists before the approver
	// mints one), populated by the time any terminal event is.
	var evidence *humangate.RecordedDecision

	// gateDetails seeds the details map every terminal event of this gate
	// shares, so none of them can drift out of naming the same subject —
	// including the §9 decision evidence, which every terminal event of a
	// webhook-decided gate therefore carries by construction rather than by
	// each call site remembering to attach it.
	gateDetails := func(extra map[string]any) map[string]any {
		d := map[string]any{"server": up.id, "tool": tool}
		if subjectDigest != "" {
			d["subject_digest"] = subjectDigest
		}
		for k, v := range evidence.Details() {
			d[k] = v
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
	decidedBy := humangate.DecidedByTerminal
	var eventOverride audit.EventType
	if ra, ok := g.approver.(ReasoningApprover); ok {
		outcome := ra.DecideWithReason(ctx, req)
		decision, eventOverride, evidence = outcome.Decision, outcome.Event, outcome.Evidence
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
		g.log(event, gateDetails(map[string]any{
			humangate.DetailDecidedBy: decidedBy, "wait_ms": waitMS}))
		forward()

	case DecisionDenied:
		event := audit.EventGateDenied
		if eventOverride != "" {
			event = eventOverride
		}
		g.log(event, gateDetails(map[string]any{
			humangate.DetailDecidedBy: decidedBy, "wait_ms": waitMS}))
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
// It is also this package's terminal-integrity chokepoint. Everything it
// prints is operator-facing plain text: nothing in internal/mcpgate emits
// styling of its own, so there is no legitimate escape sequence here to
// preserve, and sanitizing unconditionally costs nothing. That matters
// because this writer is the same one the human gate draws its prompt on and
// reads its answer beside — a gate's promise that the bytes shown are the
// bytes signed for is worth only as much as constle's hold on the screen.
//
// Two layers, because they stop different things:
//
//   - termsafe.Args escapes the interpolated values before formatting, so an
//     untrusted string (an unset url_secret_ref out of an Agentfile, a
//     reason phrase from a decision endpoint) cannot end its line and write
//     a line that reads as constle speaking. Arguments whose newlines ARE
//     constle's own say so with termsafe.Preformatted.
//   - termsafe.Block over the result is the backstop for whatever Args does
//     not reach — a %v over a composite, a future call site that forgets.
//     It cannot undo a forged line at that point, but nothing that drives a
//     terminal survives it.
//
// The dropped error is justified once here rather than at a dozen call
// sites: this writer IS the channel constle reports problems on, so a
// failure to write to it has nowhere left to be reported. Nothing the gate
// enforces depends on it either — a gated call is decided and audited
// whether or not the human ever saw the prompt.
func outf(w io.Writer, format string, args ...any) {
	termsafe.Fprintf(w, format, args...)
}

// gateLogOut is where this package's standard-library loggers land. It is a
// package var only so the test can capture it; production writes to stderr,
// like the listener error that reports the same class of background failure.
var gateLogOut io.Writer = os.Stderr

// gateLogWriter routes a standard-library logger through this package's
// chokepoint. what names which one, for the operator reading the line.
//
// It exists because these are the writers here that are not call sites.
// httputil.ReverseProxy and http.Server each do their own logging, and one
// built with no ErrorLog logs through the standard library's global logger,
// which writes straight to os.Stderr: around outf, around termsafe, inside
// the package that draws the approval prompt and reads the answer beside it.
// Nothing about those lines is constle's to compose, which is exactly why
// they have to be held.
//
// What they log is assembled from whatever the peer did. net/http quotes
// most of what it reports with %q, and %q escapes a control byte on its own
// — but that is net/http's wording, not an invariant constle may rest on,
// and crypto/x509 already does not: x509.HostnameError joins the
// certificate's DNS names verbatim, so an upstream whose certificate chains
// to a trusted CA and fails hostname verification puts those bytes on the
// screen.
//
// The logged line goes in as a value and not as preformatted text: a logger
// relaying someone else's error must not be able to open a line of its own.
// Only what names the writer is constle's own, and it says so.
type gateLogWriter struct{ what string }

func (g gateLogWriter) Write(b []byte) (int, error) {
	outf(gateLogOut, "constle: MCP gate %s: %s\n",
		termsafe.Preformatted(g.what), strings.TrimSuffix(string(b), "\n"))
	return len(b), nil
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

// errAmbiguousBody marks the refusals below — a body more than one conforming
// parser could read differently — as distinct from a body no parser can read
// at all. serveInspected audits this one and not its siblings: a truncated or
// malformed body is almost always a broken client, while a body carrying two
// spellings of the same member had to be built on purpose.
var errAmbiguousBody = errors.New("ambiguous JSON-RPC body")

// parseJSONRPC parses a single JSON-RPC message, failing closed on every body
// it cannot read exactly one way.
//
// The gate inspects one copy of the request and forwards another: forward()
// replays the ORIGINAL bytes, so the upstream runs whatever ITS parser makes
// of them. A body two conforming parsers can read differently is therefore a
// body the gate can promise nothing about, and the promise is the whole point
// — what the gate inspects has to be the call the upstream executes. Three
// families of body break that, all of them shapes encoding/json accepts in
// silence:
//
//   - A repeated member: {"params":{…rm_rf…},"params":{…echo…}}. encoding/json
//     keeps the last occurrence; a first-wins parser (gjson, buger/jsonparser,
//     simdjson's on-demand lookups, most hand-rolled scanners) keeps the
//     first. The gate then allowlists, gates, digests and audits one tool
//     while the upstream runs the other. Inside params it is worse than
//     last-wins suggests: Params is a struct, so a second params MERGES field
//     by field without zeroing, and the gate can inspect a name and an
//     arguments pair that no parser anywhere reads together.
//   - A case-variant member: {"method":"tools/call","METHOD":"tools/list"}.
//     encoding/json matches struct fields case-INSENSITIVELY, so it binds
//     METHOD to Method and the gate reads tools/list — skipping the
//     allowlist, the human gate, the meter and the tool_call bracketing
//     outright — while every case-sensitive parser (Node, Python, Jackson,
//     serde, jq, and encoding/json on the upstream's own struct) ignores
//     METHOD and runs tools/call. This family needs no exotic upstream at
//     all, and a duplicate-key check alone does not catch it: by RFC 8259
//     those are two distinct names and the document has no duplicates. The
//     fold is Unicode, not ASCII — "paramſ" (U+017F) binds to Params too —
//     so the check folds the way encoding/json folds, not the way
//     strings.ToLower does.
//   - A repeat nested inside arguments. Arguments is a json.RawMessage, so
//     both spellings survive into the approval prompt, the subject digest and
//     the upstream, where three parsers resolve them three ways: the operator
//     reads one value, signs a digest over another, and the tool acts on a
//     third. The walk therefore recurses instead of stopping at the envelope.
//
// Which spelling was "intended" is not knowable, so the gate never guesses: an
// ambiguous body is refused whole, exactly as an unparseable one is.
//
// The scan runs before the decode, and once it passes, the decode cannot
// disagree with it: every member name in the body is then unique under the
// same fold encoding/json binds with, so last-wins, first-wins and
// case-sensitive parsers all resolve the same members to the same values.
func parseJSONRPC(body []byte) (*jsonRPCMessage, error) {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, errors.New("empty JSON-RPC body")
	}
	// Checked ahead of the scan purely for the message: the scan refuses a
	// batch anyway, as a top-level value that is not a message object, but
	// "batches are not supported" tells a client what to change and "not an
	// object" does not.
	if trimmed[0] == '[' {
		return nil, errors.New("JSON-RPC batch requests are not supported through the gate proxy")
	}
	if err := scanUnambiguous(body); err != nil {
		return nil, err
	}

	var msg jsonRPCMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC body: %v", err)
	}
	if err := checkUnambiguousNames(&msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// checkUnambiguousNames refuses the two STRINGS the gate routes on when they
// are a near-miss for the spelling it compares them against.
//
// scanUnambiguous settles which bytes each member holds; this settles whether
// the gate and the upstream will read those bytes as the same name. The gate
// dispatches on exact equality ("tools/call", and the manifest's tool names),
// which is the only auditable mapping — but a value that merely differs in
// case, in surrounding whitespace, or by a trailing control byte is one an
// upstream may well fold back: method dispatch that lowercases, a name that
// crosses a C string boundary where NUL ends it. The gate would read
// "TOOLS/CALL" as some other method and forward it UNINSPECTED — no
// allowlist, no gate, no tool_call bracketing — for the upstream to run as
// tools/call. Refusing the near-miss costs nothing real: no MCP method or
// tool name contains a control character or leans on leading or trailing
// space, and an agent that means tools/call can spell it.
func checkUnambiguousNames(msg *jsonRPCMessage) error {
	if err := checkRoutingName("method", msg.Method); err != nil {
		return err
	}
	if msg.Method != methodToolsCall {
		if strings.EqualFold(msg.Method, methodToolsCall) {
			return fmt.Errorf("%w: method %q differs from %q only in case",
				errAmbiguousBody, clampJSONValue(msg.Method), methodToolsCall)
		}
		return nil
	}
	if msg.Params.Name == "" {
		// A tools/call with no tool name has nothing the gate can decide
		// about. It is refused here rather than carried, because an empty
		// name is a name the audit trail cannot hold a decision to: an
		// offline verifier requires an entry's tool and its recorded
		// request's to be present and equal, and treats an empty one as
		// absent — so a gate armed on "" would write records that are
		// correctly signed and cannot be verified. Refusing at the producer
		// keeps that requirement fail-closed instead of loosening it into
		// "absent and empty are the same thing", which is how a deleted
		// field passes for a missing one.
		return fmt.Errorf("%w: params.name is empty", errAmbiguousBody)
	}
	return checkRoutingName("params.name", msg.Params.Name)
}

// checkRoutingName rejects a routed name that a normalizing reader would see
// differently from the gate's byte-exact comparison.
func checkRoutingName(field, name string) error {
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("%w: %s %q has leading or trailing whitespace",
			errAmbiguousBody, field, clampJSONValue(name))
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s %q contains a control character",
				errAmbiguousBody, field, clampJSONValue(name))
		}
	}
	return nil
}

// maxScanDepth bounds how deep scanUnambiguous nests. It matches
// encoding/json's own limit, so the gate inspects exactly the documents a
// conforming decoder accepts — but it has to be enforced here rather than
// inherited, because json.Decoder's token stream, unlike Unmarshal, applies
// no depth limit of its own.
const maxScanDepth = 10000

// maxScanKeys bounds how many member names scanUnambiguous holds at once.
// Remembering an object's names is what makes a repeat detectable, so the
// memory the walk holds is proportional to the members of the objects
// currently OPEN: a sibling's names are released when it closes, and an array
// of a million alike rows costs the names of one row rather than of all of
// them. Nothing short of a single object with a six-figure member count
// reaches the cap. What it buys is a bounded worst case — at roughly 60 bytes
// of map and string per name the set tops out near 8 MB, the same order as
// the body already being held, where an uncapped walk over 10 MB of nothing
// but short distinct names would retain some ten times that.
const maxScanKeys = 1 << 17

// scanFrame is one open object or array: the member names already seen at that
// level, and whether the next token there is a name or a value.
type scanFrame struct {
	object  bool
	wantKey bool
	keys    map[string]string // folded name -> the spelling first seen
}

// scanUnambiguous walks the whole body once and refuses any object holding two
// member names that a parser could resolve to the same member.
//
// json.Decoder.Token is the right primitive for one reason above the others:
// it returns names already unescaped, so "name" and "name" arrive as the
// same Go string and an escape-obfuscated repeat is caught with no unescaping
// logic of the gate's own — on exactly the decoded form encoding/json itself
// matches struct fields against.
//
// The rule is the same at every depth, envelope or arguments, which is both
// simpler to state and stronger than scoping it: within one object, no two
// member names may be equal, and none may differ from another only under
// Unicode simple folding. Two names that collide that way are left for the
// reader to resolve, and the readers disagree.
func scanUnambiguous(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	// Numbers are carried as text rather than parsed into float64: an id or an
	// argument may legitimately be 1e999, which the gate never reads as a
	// number and Unmarshal never rejects, and the scan must not be the one
	// that refuses it.
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON-RPC body: %v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		// Unmarshal accepts a top-level null into a zero-value message, whose
		// empty method is not tools/call and so skips inspection entirely.
		return errors.New("invalid JSON-RPC body: top-level value is not a JSON-RPC message object")
	}

	stack := []scanFrame{{object: true, wantKey: true}}
	tracked := 0

	for len(stack) > 0 {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON-RPC body: %v", err)
		}
		top := &stack[len(stack)-1]

		if top.object && top.wantKey {
			if d, ok := tok.(json.Delim); ok {
				if d != '}' {
					// Unreachable: in name position the lexer yields a string
					// or the closing brace, nothing else.
					return fmt.Errorf("invalid JSON-RPC body: unexpected %q where a member name belongs", d)
				}
				tracked -= len(top.keys)
				stack = stack[:len(stack)-1]
				continue
			}
			key, ok := tok.(string)
			if !ok {
				return errors.New("invalid JSON-RPC body: member name is not a string")
			}
			folded := foldKey(key)
			if seen, dup := top.keys[folded]; dup {
				if seen == key {
					return fmt.Errorf("%w: member %q appears more than once at depth %d",
						errAmbiguousBody, clampJSONValue(key), len(stack)-1)
				}
				return fmt.Errorf("%w: members %q and %q at depth %d differ only in case",
					errAmbiguousBody, clampJSONValue(seen), clampJSONValue(key), len(stack)-1)
			}
			if top.keys == nil {
				top.keys = make(map[string]string, 4)
			}
			top.keys[folded] = key
			tracked++
			if tracked > maxScanKeys {
				return errors.New("invalid JSON-RPC body: too many member names to inspect")
			}
			top.wantKey = false
			continue
		}

		// A value position: an array element, or the value of the name just
		// read. Putting the parent back into name position BEFORE descending
		// is what keeps the walk iterative — there is then nothing to remember
		// across the pop, and a 10000-deep body costs heap the cap bounds
		// rather than goroutine stack it does not.
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if top.object {
					top.wantKey = true
				}
				if len(stack) >= maxScanDepth {
					return errors.New("invalid JSON-RPC body: nested too deeply to inspect")
				}
				stack = append(stack, scanFrame{object: d == '{', wantKey: d == '{'})
			case ']':
				stack = stack[:len(stack)-1]
			default:
				// Unreachable: '}' cannot open a value.
				return fmt.Errorf("invalid JSON-RPC body: unexpected %q where a value belongs", d)
			}
			continue
		}
		if top.object {
			top.wantKey = true
		}
	}

	// Token is a stream decoder and reports nothing after a complete value, so
	// a second message appended to the first has to be asked about. Unmarshal
	// rejects trailing data too, but the scan runs first and so is the one
	// that gets there.
	if dec.More() {
		return errors.New("invalid JSON-RPC body: trailing data after the JSON-RPC message")
	}
	return nil
}

// foldKey returns the spelling shared by every member name encoding/json would
// bind to the same struct field: each rune replaced by the smallest rune it
// folds to, lowercased when that is an ASCII letter so the common all-ASCII
// name is returned unchanged and costs no allocation.
//
// It has to be simple folding rather than lowercasing, because that is what
// encoding/json does: U+017F LATIN SMALL LETTER LONG S folds to "s" and
// U+212A KELVIN SIGN to "k", so {"params":…,"paramſ":…} binds twice while
// strings.ToLower reads two unrelated names. Folding maps each equivalence
// class to one representative, so comparing folded spellings answers exactly
// the question strings.EqualFold answers pairwise, at map-lookup cost.
func foldKey(key string) string {
	simple := true
	for i := 0; i < len(key); i++ {
		if c := key[i]; c >= utf8.RuneSelf || ('A' <= c && c <= 'Z') {
			simple = false
			break
		}
	}
	if simple {
		return key
	}
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		b.WriteRune(foldRune(r))
	}
	return b.String()
}

// foldRune is the representative of one simple-folding equivalence class: the
// smallest rune in it, shifted to lower case when that smallest rune is an
// ASCII letter (every ASCII letter's class holds its own upper case, so no
// other class can claim the shifted value).
func foldRune(r rune) rune {
	if r < utf8.RuneSelf {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}
	lo := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < lo {
			lo = f
		}
	}
	if 'A' <= lo && lo <= 'Z' {
		lo += 'a' - 'A'
	}
	return lo
}

// clampJSONValue bounds a member name or a routed name before it is echoed
// back to the agent, on the same principle as clampMethod and compactRPCID:
// the body cap allows a very long one, and a truncated multi-byte rune is
// dropped rather than emitted as a broken one.
func clampJSONValue(s string) string {
	const maxLen = 64
	if len(s) > maxLen {
		s = strings.ToValidUTF8(s[:maxLen], "")
	}
	return s
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
