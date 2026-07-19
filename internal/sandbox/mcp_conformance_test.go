package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/mcpgate"
	"github.com/constle/constle/pkg/manifest"
)

// ============================================================
// mcp_conformance_test.go — adversarial MCP gate-enforcement parity
//
// Same rigor as conformance_test.go, aimed at the MCP gate proxy. A stub
// MCP server listens on 0.0.0.0 on the host — deliberately exposed on every
// interface, so the ONLY thing standing between the agent and the real
// server is the sandbox network policy plus the gate. Scenarios, each run
// against every available backend with identical required outcomes:
//
//	deny:     ungated tool passes, gated tool is denied, and every attempt
//	          to reach the real server directly (proxied, direct, via the
//	          gateway) fails — the stub must never see "bypass_tool"
//	approve:  an approved gated tool call reaches the real server
//	timeout:  an unanswered gate times out, the call never reaches the
//	          real server, and on_timeout: abort kills the run
//	gatekill: the gate proxy dies mid-flight while a gated call waits for
//	          approval — the call fails closed, nothing leaks upstream
//
// Gated behind CONSTLE_E2E=1 because the scenarios start real sandboxes:
//
//	sudo -E CONSTLE_E2E=1 go test ./internal/sandbox/ -run MCP -v
// ============================================================

// mcpStub is the "real" MCP server the agent must never reach directly.
type mcpStub struct {
	mu    sync.Mutex
	tools []string // tool names of every tools/call that arrived
	addr  net.Listener
	srv   *http.Server
}

func startMCPStub(t *testing.T) *mcpStub {
	t.Helper()
	// 0.0.0.0 on purpose: reachable on every host interface, including the
	// Docker bridge gateways and the Firecracker TAP gateway. Only the
	// sandbox network policy stands between the agent and this listener.
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("mcp stub listen: %v", err)
	}

	stub := &mcpStub{addr: ln}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&msg); err == nil && msg.Method == "tools/call" {
			stub.mu.Lock()
			stub.tools = append(stub.tools, msg.Params.Name)
			stub.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"done"}]}}`)
	})
	stub.srv = &http.Server{Handler: mux}
	go stub.srv.Serve(ln)
	t.Cleanup(func() { stub.srv.Close() })
	return stub
}

func (s *mcpStub) port() int { return s.addr.Addr().(*net.TCPAddr).Port }

func (s *mcpStub) calledTools() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.tools...)
}

// scriptedApprover resolves every gate with a fixed decision, or never
// (decision DecisionNone + hang=true) to force timeouts.
type scriptedApprover struct {
	decision mcpgate.Decision
	hang     bool
}

func (a *scriptedApprover) Decide(ctx context.Context, req mcpgate.Request) mcpgate.Decision {
	if a.hang {
		<-ctx.Done()
		return mcpgate.DecisionNone
	}
	return a.decision
}

// signalingApprover hangs like a human who never answers, but closes
// triggered the moment the gate consults it — the cue for mid-flight
// gate-kill scenarios.
type signalingApprover struct {
	triggered chan struct{}
	once      sync.Once
}

func (a *signalingApprover) Decide(ctx context.Context, req mcpgate.Request) mcpgate.Decision {
	a.once.Do(func() { close(a.triggered) })
	<-ctx.Done()
	return mcpgate.DecisionNone
}

// mcpTestManifest declares one MCP server "testsrv" with an ungated
// free_tool and a gated gated_tool, an empty network allowlist (the gate
// route must be the sandbox's only way out), and the given agent script.
func mcpTestManifest(script string, approvalTimeoutSeconds int) *manifest.AgentManifest {
	return &manifest.AgentManifest{
		APIVersion: "constle.dev/v1alpha1",
		Kind:       "AgentManifest",
		Identity:   manifest.Identity{Name: "mcp-gate-test", Version: "1.0.0"},
		Sandbox: manifest.Sandbox{
			Image:    "curlimages/curl:latest",
			MemoryMB: 128,
			Command:  []string{"sh", "-c", script},
			Network:  manifest.Network{Egress: "restricted"},
		},
		Capabilities: []manifest.Capability{manifest.CapExternalAPI},
		MCP: manifest.MCP{Servers: []manifest.MCPServer{
			// URL host is loopback: even if it leaked, the sandbox has no
			// route to the host's loopback. The stub's real exposure is via
			// the bridge/TAP gateways, which the script attacks explicitly.
			{ID: "testsrv", URL: "", Tools: []string{"free_tool", "gated_tool"}},
		}},
		HumanGates: manifest.HumanGates{
			Enabled:                true,
			RequireApprovalFor:     []string{"gated_tool"},
			ApprovalTimeoutSeconds: approvalTimeoutSeconds,
			OnTimeout:              "abort",
		},
	}
}

// mcpCallHelper is the shared shell prologue: call <url> <tool> POSTs a
// tools/call and prints the response body.
const mcpCallHelper = `
call() {
  curl -s --max-time 20 -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":{\"n\":1}}}" \
    "$1" 2>&1
}
`

// runMCPScenario wires a gate + backend, runs the manifest, and returns the
// agent output plus all audit events. afterStart (optional) runs once the
// sandbox is up — scenario hooks use it to kill the gate mid-flight etc.
func runMCPScenario(t *testing.T, backend SandboxBackend, m *manifest.AgentManifest,
	approver mcpgate.Approver, afterStart func(runCtx *RunContext, gate *mcpgate.Gate)) (string, []audit.Entry) {
	t.Helper()

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New(logPath)
	if err != nil {
		t.Fatalf("cannot create audit logger: %v", err)
	}
	defer logger.Close()

	gate, err := mcpgate.New(m, approver, nil, logger, nil)
	if err != nil {
		t.Fatalf("mcpgate.New: %v", err)
	}
	defer gate.Close()

	setter, ok := backend.(MCPGateSetter)
	if !ok {
		t.Fatalf("backend %T does not implement MCPGateSetter", backend)
	}
	setter.SetMCPGate(gate)

	runCtx, err := backend.Start(m)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer backend.Stop(runCtx)

	// on_timeout: abort must terminate the run, exactly as the CLI wires it.
	gate.SetAbortRun(func() {
		t.Logf("gate abort: killing run %s", runCtx.RunID)
		if err := backend.Kill(runCtx); err != nil {
			t.Logf("gate abort: Kill failed: %v", err)
		}
	})

	if afterStart != nil {
		afterStart(runCtx, gate)
	}

	done := make(chan struct{})
	go func() {
		backend.Wait(runCtx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Minute):
		backend.Kill(runCtx)
		t.Fatalf("scenario did not finish within 3 minutes")
	}

	logs, err := backend.Logs(runCtx)
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("cannot read audit log: %v", err)
	}
	var events []audit.Entry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var entry audit.Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("corrupt audit line %q: %v", line, err)
		}
		if entry.RunID != runCtx.RunID {
			t.Errorf("audit event attributed to run %q, want %q", entry.RunID, runCtx.RunID)
		}
		events = append(events, entry)
	}

	if os.Getenv("CONSTLE_E2E_VERBOSE") == "1" {
		fmt.Printf("---- %T output ----\n%s\n-------------------\n", backend, logs)
	}
	return string(logs), events
}

func countEvents(events []audit.Entry, et audit.EventType) int {
	n := 0
	for _, e := range events {
		if e.Event == et {
			n++
		}
	}
	return n
}

// TestMCPGateDenyAndBypass is the core adversarial scenario: gated call is
// denied, ungated call works, and every route to the real MCP server other
// than the gate fails — on both backends, with identical outcomes.
func TestMCPGateDenyAndBypass(t *testing.T) {
	requireE2E(t)

	// BypassAllFailed is a bool, not a count: the number of attempted routes
	// legitimately differs per backend (Firecracker guests also probe the
	// TAP gateway), but "every attempt failed" must hold on both.
	type outcome struct {
		FreeOK, GateDenied, BypassSucceeded, BypassAllFailed bool
	}
	outcomes := map[string]outcome{}

	for name, backend := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			stub := startMCPStub(t)

			script := mcpCallHelper + fmt.Sprintf(`
REAL_PORT=%d
echo "=== MCP gate enforcement tests ==="

echo "Test 1: ungated tool through the gate"
RESP=$(call "$CONSTLE_MCP_TESTSRV_URL" free_tool)
echo "$RESP" | grep -q '"result"' && echo "GATE_FREE: OK" || echo "GATE_FREE: BROKEN — $RESP"

echo "Test 2: gated tool through the gate (deny expected)"
RESP=$(call "$CONSTLE_MCP_TESTSRV_URL" gated_tool)
echo "$RESP" | grep -q 'DENIED' && echo "GATE_DENIED: YES" || echo "GATE_DENIED: NO — $RESP"

echo "Test 3: reach the real MCP server through the egress proxy"
for HOST in host.docker.internal $CONSTLE_GATEWAY_IP; do
  RESP=$(call "http://$HOST:$REAL_PORT/mcp" bypass_tool)
  echo "$RESP" | grep -q '"result"' \
    && echo "BYPASS: SUCCEEDED — real server reachable via proxy ($HOST)" \
    || echo "BYPASS: FAILED via proxy ($HOST)"
done

echo "Test 4: reach the real MCP server directly, proxy env unset"
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy
for HOST in host.docker.internal $CONSTLE_GATEWAY_IP; do
  RESP=$(call "http://$HOST:$REAL_PORT/mcp" bypass_tool)
  echo "$RESP" | grep -q '"result"' \
    && echo "BYPASS: SUCCEEDED — real server reachable directly ($HOST)" \
    || echo "BYPASS: FAILED direct ($HOST)"
done
`, stub.port())

			m := mcpTestManifest(script, 300)
			m.MCP.Servers[0].URL = fmt.Sprintf("http://127.0.0.1:%d/mcp", stub.port())

			output, events := runMCPScenario(t, backend,
				m, &scriptedApprover{decision: mcpgate.DecisionDenied}, nil)

			bypassFailed := strings.Count(output, "BYPASS: FAILED")
			o := outcome{
				FreeOK:          strings.Contains(output, "GATE_FREE: OK"),
				GateDenied:      strings.Contains(output, "GATE_DENIED: YES"),
				BypassSucceeded: strings.Contains(output, "BYPASS: SUCCEEDED"),
				BypassAllFailed: bypassFailed >= 2 && !strings.Contains(output, "BYPASS: SUCCEEDED"),
			}
			outcomes[name] = o

			if !o.FreeOK {
				t.Errorf("[%s] ungated tool did not pass through the gate:\n%s", name, output)
			}
			if !o.GateDenied {
				t.Errorf("[%s] gated tool was not denied:\n%s", name, output)
			}
			if o.BypassSucceeded {
				t.Errorf("[%s] agent reached the real MCP server, bypassing the gate:\n%s", name, output)
			}
			if bypassFailed < 2 {
				t.Errorf("[%s] want ≥2 failed bypass attempts, got %d:\n%s", name, bypassFailed, output)
			}

			// The stub is the ground truth: only the ungated tool may arrive.
			tools := stub.calledTools()
			if len(tools) != 1 || tools[0] != "free_tool" {
				t.Errorf("[%s] real MCP server saw %v, want exactly [free_tool]", name, tools)
			}

			if countEvents(events, audit.EventGateTriggered) != 1 ||
				countEvents(events, audit.EventGateDenied) != 1 {
				t.Errorf("[%s] want 1 gate_triggered + 1 gate_denied, got %+v", name, events)
			}
		})
	}

	if len(outcomes) < 2 {
		t.Skipf("only %d backend(s) available — parity comparison skipped", len(outcomes))
	}
	if outcomes["docker"] != outcomes["firecracker"] {
		t.Errorf("backends disagree on MCP gate outcomes:\n  docker:      %+v\n  firecracker: %+v",
			outcomes["docker"], outcomes["firecracker"])
	}
}

// TestMCPGateApprove proves an approval lets the call through to the real
// server — the gate is a gate, not a wall.
func TestMCPGateApprove(t *testing.T) {
	requireE2E(t)

	for name, backend := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			stub := startMCPStub(t)

			script := mcpCallHelper + `
RESP=$(call "$CONSTLE_MCP_TESTSRV_URL" gated_tool)
echo "$RESP" | grep -q '"result"' && echo "GATE_APPROVED: YES" || echo "GATE_APPROVED: NO — $RESP"
`
			m := mcpTestManifest(script, 300)
			m.MCP.Servers[0].URL = fmt.Sprintf("http://127.0.0.1:%d/mcp", stub.port())

			output, events := runMCPScenario(t, backend,
				m, &scriptedApprover{decision: mcpgate.DecisionApproved}, nil)

			if !strings.Contains(output, "GATE_APPROVED: YES") {
				t.Errorf("[%s] approved gated call did not succeed:\n%s", name, output)
			}
			if tools := stub.calledTools(); len(tools) != 1 || tools[0] != "gated_tool" {
				t.Errorf("[%s] real MCP server saw %v, want exactly [gated_tool]", name, tools)
			}
			if countEvents(events, audit.EventGateApproved) != 1 {
				t.Errorf("[%s] want 1 gate_approved event, got %+v", name, events)
			}
		})
	}
}

// TestMCPGateTimeoutAbort proves an unanswered gate times out, the call
// never reaches the real server, and on_timeout: abort terminates the run.
func TestMCPGateTimeoutAbort(t *testing.T) {
	requireE2E(t)

	for name, backend := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			stub := startMCPStub(t)

			script := mcpCallHelper + `
RESP=$(call "$CONSTLE_MCP_TESTSRV_URL" gated_tool)
echo "GATE_TIMEOUT_RESPONSE: $RESP"
# The run is aborted by the gate; sleep long enough that a non-aborted
# run would be distinguishable.
sleep 60
echo "RUN_SURVIVED_ABORT"
`
			m := mcpTestManifest(script, 5)
			m.MCP.Servers[0].URL = fmt.Sprintf("http://127.0.0.1:%d/mcp", stub.port())

			start := time.Now()
			output, events := runMCPScenario(t, backend,
				m, &scriptedApprover{hang: true}, nil)
			elapsed := time.Since(start)

			if strings.Contains(output, "RUN_SURVIVED_ABORT") {
				t.Errorf("[%s] run survived a gate timeout with on_timeout=abort:\n%s", name, output)
			}
			if tools := stub.calledTools(); len(tools) != 0 {
				t.Errorf("[%s] timed-out call reached the real MCP server: %v", name, tools)
			}
			if countEvents(events, audit.EventGateTimeout) != 1 {
				t.Errorf("[%s] want 1 gate_timeout event, got %+v", name, events)
			}
			if elapsed > 90*time.Second {
				t.Errorf("[%s] abort took %v — the 5s gate timeout did not terminate the run", name, elapsed)
			}
		})
	}
}

// TestMCPGateKilledMidFlight is the E2E half of the gate-death check: the
// gate proxy dies while a gated call is parked awaiting approval. The
// agent's call must fail closed — never pass through to the real server —
// and the agent must not be able to reconnect.
func TestMCPGateKilledMidFlight(t *testing.T) {
	requireE2E(t)

	for name, backend := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			stub := startMCPStub(t)

			script := mcpCallHelper + `
RESP=$(call "$CONSTLE_MCP_TESTSRV_URL" gated_tool)
if echo "$RESP" | grep -q '"result"'; then
  echo "GATE_DEAD: LEAKED — $RESP"
else
  echo "GATE_DEAD: CALL_FAILED"
fi
RESP2=$(call "$CONSTLE_MCP_TESTSRV_URL" free_tool)
echo "$RESP2" | grep -q '"result"' && echo "GATE_DEAD: RECONNECTED" || echo "GATE_DEAD: UNREACHABLE"
`
			m := mcpTestManifest(script, 300)
			m.MCP.Servers[0].URL = fmt.Sprintf("http://127.0.0.1:%d/mcp", stub.port())

			// Hang the approver so the gated call parks inside the gate; it
			// signals the moment the gate consults it, and that signal
			// triggers the kill — mid-flight, approval pending.
			approver := &signalingApprover{triggered: make(chan struct{})}
			afterStart := func(runCtx *RunContext, gate *mcpgate.Gate) {
				go func() {
					select {
					case <-approver.triggered:
						gate.Close()
					case <-time.After(2 * time.Minute):
					}
				}()
			}

			output, _ := runMCPScenario(t, backend, m, approver, afterStart)

			if strings.Contains(output, "GATE_DEAD: LEAKED") {
				t.Errorf("[%s] gated call passed through after gate death:\n%s", name, output)
			}
			if !strings.Contains(output, "GATE_DEAD: CALL_FAILED") {
				t.Errorf("[%s] in-flight call did not fail closed:\n%s", name, output)
			}
			if !strings.Contains(output, "GATE_DEAD: UNREACHABLE") {
				t.Errorf("[%s] agent reconnected to a dead gate:\n%s", name, output)
			}
			if tools := stub.calledTools(); len(tools) != 0 {
				t.Errorf("[%s] real MCP server saw %v after gate death, want nothing", name, tools)
			}
		})
	}
}
