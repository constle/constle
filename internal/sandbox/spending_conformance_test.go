package sandbox

import (
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
	"github.com/constle/constle/internal/spending"
	"github.com/constle/constle/pkg/manifest"
)

// ============================================================
// spending_conformance_test.go — adversarial spending enforcement parity
//
// Same rigor as mcp_conformance_test.go, aimed at the spending meter. A
// priced stub MCP server reports whatever usage the test scripts — the
// inflation scenario makes it report absurd usage so the FIRST response
// already crosses max_per_run_usd. Required outcome on BOTH backends,
// identically:
//
//   - the crossing response is still delivered (metering is post-hoc),
//   - the agent's NEXT call fails at the tripped gate — before/regardless
//     of the kill landing,
//   - the run is killed through backend.Kill (never survives its sleep),
//   - the stub sees exactly one tools/call,
//   - a spending_limit_reached (severity=limit) audit event is written.
//
//	sudo -E CONSTLE_E2E=1 go test ./internal/sandbox/ -run Spending -v
// ============================================================

// pricedStub is an MCP server whose every tools/call response reports the
// configured usage units.
type pricedStub struct {
	mu    sync.Mutex
	tools []string
	units int64
	addr  net.Listener
	srv   *http.Server
}

func startPricedStub(t *testing.T, units int64) *pricedStub {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("priced stub listen: %v", err)
	}
	stub := &pricedStub{units: units, addr: ln}
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
		id := "1"
		if len(msg.ID) > 0 {
			id = string(msg.ID)
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"done"}],"usage":{"units":%d}}}`+"\n", id, stub.units)
	})
	stub.srv = &http.Server{Handler: mux}
	go stub.srv.Serve(ln)
	t.Cleanup(func() { stub.srv.Close() })
	return stub
}

func (s *pricedStub) port() int { return s.addr.Addr().(*net.TCPAddr).Port }

func (s *pricedStub) calledTools() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.tools...)
}

// spendTestManifest declares one priced MCP server ("paidsrv", $0.01/unit
// on result.usage.units) and a per-run cap of $0.50. Human gates are off —
// only spending enforcement is under test.
func spendTestManifest(script string, stubPort int) *manifest.AgentManifest {
	return &manifest.AgentManifest{
		APIVersion: "constle.dev/v1alpha1",
		Kind:       "AgentManifest",
		Identity:   manifest.Identity{Name: "spending-test", Version: "1.0.0"},
		Sandbox: manifest.Sandbox{
			Image:    "curlimages/curl:latest",
			MemoryMB: 128,
			Command:  []string{"sh", "-c", script},
			Network:  manifest.Network{Egress: "restricted"},
		},
		Capabilities: []manifest.Capability{manifest.CapExternalAPI},
		MCP: manifest.MCP{Servers: []manifest.MCPServer{{
			ID:  "paidsrv",
			URL: fmt.Sprintf("http://127.0.0.1:%d/mcp", stubPort),
			Pricing: &manifest.MCPPricing{Meters: []manifest.PriceMeter{
				{UsagePath: "result.usage.units", USDPerUnit: "0.01"},
			}},
		}}},
		Spending: manifest.Spending{MaxPerRunUSD: "0.50"},
	}
}

// runSpendScenario wires tracker + gate + backend exactly as the CLI does
// (SetSpendKill → backend.Kill), runs the manifest, and returns the agent
// output plus audit events.
func runSpendScenario(t *testing.T, backend SandboxBackend, m *manifest.AgentManifest,
	limits spending.Limits, store *spending.DailyStore) (string, []audit.Entry) {
	t.Helper()

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New(logPath)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer logger.Close()

	tracker, err := spending.NewTracker(limits, store)
	if err != nil {
		t.Fatalf("NewTracker: %v", err)
	}

	gate, err := mcpgate.New(m, nil, nil, logger, tracker)
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

	var killOnce sync.Once
	gate.SetSpendKill(func() {
		killOnce.Do(func() {
			t.Logf("spending kill: stopping run %s (%s)", runCtx.RunID, tracker.Tripped())
			if err := backend.Kill(runCtx); err != nil {
				t.Logf("spending kill: Kill failed: %v", err)
			}
		})
	})

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
		events = append(events, entry)
	}
	return string(logs), events
}

// TestSpendingInflatedUsageKillsRun is the core adversarial scenario: a
// priced server reports inflated usage ($100 on the first call, against a
// $0.50 per-run cap). The run must be ACTUALLY killed — proven by the agent
// failing to complete its second call and never reaching its survival
// marker — identically on both backends.
func TestSpendingInflatedUsageKillsRun(t *testing.T) {
	requireE2E(t)

	// The agent's own stdout is deliberately NOT part of the required
	// outcome: a hard kill can (and on Firecracker does) outrun the guest's
	// output flush. The proof lives host-side, where the kill cannot erase
	// it: the stub's call count (ground truth that no further call
	// completed), the audit log, and the run not surviving its sleep.
	type outcome struct {
		Survived     bool
		StubCalls    int
		LimitEvents  int
		KilledInTime bool
	}
	outcomes := map[string]outcome{}

	for name, backend := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			// 10000 units × $0.01 = $100 per call ≫ $0.50 per-run cap.
			stub := startPricedStub(t, 10000)

			// The agent proves it is alive by CALLING, so its death is
			// visible at the stub: call once (crosses the cap), give the
			// async metering 2s to trip, then keep trying every second for
			// a minute. Any completed later call would raise the stub count.
			script := mcpCallHelper + `
call "$CONSTLE_MCP_PAIDSRV_URL" expensive_tool >/dev/null 2>&1
sleep 2
i=0
while [ $i -lt 60 ]; do
  call "$CONSTLE_MCP_PAIDSRV_URL" expensive_tool >/dev/null 2>&1
  i=$((i+1))
  sleep 1
done
echo "RUN_SURVIVED_SPENDING_KILL"
`
			m := spendTestManifest(script, stub.port())

			start := time.Now()
			output, events := runSpendScenario(t, backend, m,
				spending.Limits{PerRun: 50_000_000}, nil) // $0.50
			elapsed := time.Since(start)

			var limitEvents int
			for _, e := range events {
				if e.Event == audit.EventSpendingLimit && e.Details["severity"] == "limit" {
					limitEvents++
					if e.Details["limit"] != string(spending.ViolationPerRun) {
						t.Errorf("[%s] limit event names %v, want max_per_run_usd", name, e.Details["limit"])
					}
				}
			}

			o := outcome{
				Survived:     strings.Contains(output, "RUN_SURVIVED_SPENDING_KILL"),
				StubCalls:    len(stub.calledTools()),
				LimitEvents:  limitEvents,
				KilledInTime: elapsed <= 90*time.Second,
			}
			outcomes[name] = o

			if o.Survived {
				t.Errorf("[%s] run survived the spending kill:\n%s", name, output)
			}
			if o.StubCalls != 1 {
				t.Errorf("[%s] real MCP server saw %d tools/calls (%v), want exactly 1 — no call may complete after the cap was crossed",
					name, o.StubCalls, stub.calledTools())
			}
			if o.LimitEvents != 1 {
				t.Errorf("[%s] want exactly 1 spending limit audit event, got %d", name, o.LimitEvents)
			}
			if !o.KilledInTime {
				t.Errorf("[%s] run took %v — the kill did not interrupt the agent's 60-attempt loop", name, elapsed)
			}
		})
	}

	if len(outcomes) < 2 {
		t.Skipf("only %d backend(s) available — parity comparison skipped", len(outcomes))
	}
	if outcomes["docker"] != outcomes["firecracker"] {
		t.Errorf("backends disagree on spending enforcement:\n  docker:      %+v\n  firecracker: %+v",
			outcomes["docker"], outcomes["firecracker"])
	}
}
