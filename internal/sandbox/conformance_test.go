package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/pkg/manifest"
)

// ============================================================
// conformance_test.go — adversarial network-enforcement parity
//
// Runs the bypass scenarios from spec/bypass-test.yaml against every
// available backend and requires IDENTICAL, designed results:
//
//	Test 1  non-allowlisted host through the proxy   → BLOCKED: YES
//	Test 2  unset proxy env vars, connect directly    → BYPASS: FAILED
//	Test 3  connect to a raw IP (DNS + IP-literal)    → BYPASS: FAILED
//
// Gated behind CONSTLE_E2E=1 because the scenarios start real sandboxes
// (Docker containers / Firecracker microVMs):
//
//	sudo -E CONSTLE_E2E=1 go test ./internal/sandbox/ -run Conformance -v
// ============================================================

// bypassOutcome captures the security-relevant markers of one bypass run.
type bypassOutcome struct {
	Test1Blocked      bool // "BLOCKED: YES" seen
	BypassSucceeded   bool // any "BYPASS: SUCCEEDED" seen (must never be)
	BypassFailedCount int  // "BYPASS: FAILED" occurrences (want 2)
}

func conformanceBackends(t *testing.T) map[string]SandboxBackend {
	backends := map[string]SandboxBackend{}
	if dockerAvailable() {
		backends["docker"] = &DockerBackend{}
	} else {
		t.Log("docker unavailable — skipping docker conformance")
	}
	if reason := firecrackerUnavailableReason(); reason == "" {
		backends["firecracker"] = &FirecrackerBackend{}
	} else {
		t.Logf("firecracker unavailable — skipping firecracker conformance: %s", reason)
	}
	return backends
}

func requireE2E(t *testing.T) {
	if os.Getenv("CONSTLE_E2E") != "1" {
		t.Skip("set CONSTLE_E2E=1 to run conformance tests (starts real sandboxes)")
	}
}

func TestConformanceBypassScenarios(t *testing.T) {
	requireE2E(t)

	m, err := manifest.ParseFile(filepath.Join("..", "..", "spec", "bypass-test.yaml"))
	if err != nil {
		t.Fatalf("cannot parse spec/bypass-test.yaml: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("spec/bypass-test.yaml invalid: %v", err)
	}

	outcomes := map[string]bypassOutcome{}

	for name, backend := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			output, events := runConformanceScenario(t, backend, m)

			outcome := bypassOutcome{
				Test1Blocked:      strings.Contains(output, "BLOCKED: YES"),
				BypassSucceeded:   strings.Contains(output, "BYPASS: SUCCEEDED"),
				BypassFailedCount: strings.Count(output, "BYPASS: FAILED"),
			}
			outcomes[name] = outcome

			if !outcome.Test1Blocked {
				t.Errorf("[%s] non-allowlisted host was not blocked:\n%s", name, output)
			}
			if outcome.BypassSucceeded {
				t.Errorf("[%s] a bypass attempt SUCCEEDED:\n%s", name, output)
			}
			if outcome.BypassFailedCount != 2 {
				t.Errorf("[%s] want 2 failed bypass attempts, got %d:\n%s",
					name, outcome.BypassFailedCount, output)
			}

			// The proxy must have observed (and denied) the Test 1 attempt,
			// and the audit pipeline must attribute it to this run.
			blocked := 0
			for _, event := range events {
				if event.Event == audit.EventNetworkBlocked {
					blocked++
				}
			}
			if blocked == 0 {
				t.Errorf("[%s] no network_blocked audit events recorded", name)
			}
		})
	}

	if len(outcomes) < 2 {
		t.Skipf("only %d backend(s) available — parity comparison skipped", len(outcomes))
	}
	if outcomes["docker"] != outcomes["firecracker"] {
		t.Errorf("backends disagree on bypass outcomes:\n  docker:      %+v\n  firecracker: %+v",
			outcomes["docker"], outcomes["firecracker"])
	}
}

func TestConformanceAllowedTraffic(t *testing.T) {
	requireE2E(t)

	m := &manifest.AgentManifest{
		APIVersion: "constle.dev/v1alpha1",
		Kind:       "AgentManifest",
		Identity:   manifest.Identity{Name: "allowed-traffic-test", Version: "1.0.0"},
		Sandbox: manifest.Sandbox{
			Image:    "curlimages/curl:latest",
			MemoryMB: 128,
			Command: []string{"sh", "-c",
				`curl -sf --max-time 30 https://httpbin.org/get > /dev/null ` +
					`&& echo "ALLOWED: YES" || echo "ALLOWED: NO"`},
			Network: manifest.Network{
				Egress:       "restricted",
				AllowedHosts: []string{"httpbin.org"},
			},
		},
		Capabilities: []manifest.Capability{manifest.CapWebSearch},
	}

	results := map[string]bool{}

	for name, backend := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			output, events := runConformanceScenario(t, backend, m)

			allowed := strings.Contains(output, "ALLOWED: YES")
			results[name] = allowed
			if !allowed {
				t.Errorf("[%s] allowlisted host was not reachable through the proxy:\n%s", name, output)
			}

			seenAllowedEvent := false
			for _, event := range events {
				if event.Event == audit.EventNetworkAllowed {
					seenAllowedEvent = true
				}
			}
			if !seenAllowedEvent {
				t.Errorf("[%s] no network_allowed audit event recorded", name)
			}
		})
	}

	if len(results) == 2 && results["docker"] != results["firecracker"] {
		t.Errorf("backends disagree on allowed traffic: %+v", results)
	}
}

// runConformanceScenario starts the manifest on the given backend, waits
// for completion (with a hard timeout), and returns the agent output plus
// the audit events flushed from the run's Squid log.
func runConformanceScenario(t *testing.T, backend SandboxBackend, m *manifest.AgentManifest) (string, []audit.Entry) {
	t.Helper()

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New(logPath)
	if err != nil {
		t.Fatalf("cannot create audit logger: %v", err)
	}
	defer logger.Close()

	runCtx, err := backend.Start(m)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer backend.Stop(runCtx)

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

	// Flush network events the same way the CLI does, then read them back.
	if runCtx.SquidAccessLog != "" {
		err = audit.FlushSquidLogFile(runCtx.RunID, m.Identity.Name, runCtx.SquidAccessLog, logger)
	} else {
		err = audit.FlushSquidLogs(runCtx.RunID, m.Identity.Name, runCtx.ProxyContainerID, logger)
	}
	if err != nil {
		t.Logf("note: flushing squid logs failed (may mean no proxy traffic at all): %v", err)
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

	if verbose := os.Getenv("CONSTLE_E2E_VERBOSE"); verbose == "1" {
		fmt.Printf("---- %T output ----\n%s\n-------------------\n", backend, logs)
	}
	return string(logs), events
}
