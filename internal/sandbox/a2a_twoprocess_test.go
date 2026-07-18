package sandbox

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/constle/constle/internal/a2a"
	"github.com/constle/constle/internal/identity"
)

// ============================================================
// a2a_twoprocess_test.go — the real two-machine deliverable
//
// Two INDEPENDENT `constle run` invocations (each its own OS process, own
// DID, own audit log), simulating two separate machines, complete a genuine
// signed, mutually-authenticated A2A round trip when each declares the other
// as a peer. A separate test proves the two-process replay guarantee: the
// exact same validly signed envelope, sent twice within one receiver run, is
// accepted once and rejected the second time.
//
// These exec the real binary rather than wiring gates in-process, because
// "two independent constle run invocations" is the property under test.
//
//	sudo -E CONSTLE_E2E=1 go test ./internal/sandbox/ -run A2A -v
// ============================================================

// buildConstle builds the constle binary once per test into a temp dir and
// returns its path.
func buildConstle(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "constle")
	out, err := exec.Command("go", "build", "-o", bin, "../../cmd/constle").CombinedOutput()
	if err != nil {
		t.Fatalf("go build constle: %v\n%s", err, out)
	}
	return bin
}

// getOrCreateIdentity returns the DID for a persistent test identity,
// creating it if this machine does not have it yet.
func getOrCreateIdentity(t *testing.T, name string) string {
	t.Helper()
	if id, err := identity.Load(name); err == nil {
		return id.DID()
	}
	id, err := identity.Create(name, "")
	if err != nil {
		t.Fatalf("create identity %q: %v", name, err)
	}
	return id.DID()
}

// writeAgentfile writes content to a temp .yaml and returns its path.
func writeAgentfile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// waitForTCPUp polls addr until something accepts, or fails the test.
func waitForTCPUp(t *testing.T, addr string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s within %s", addr, within)
}

// TestA2ATwoProcessRoundTrip is the final deliverable: two separate
// `constle run` processes, each with its own DID, each declaring the other,
// complete a signed round trip end to end — on both backends.
func TestA2ATwoProcessRoundTrip(t *testing.T) {
	requireE2E(t)

	bin := buildConstle(t)
	aDID := getOrCreateIdentity(t, "a2a-e2e-a")
	bDID := getOrCreateIdentity(t, "a2a-e2e-b")

	for name := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			listenAddr := freeLoopbackAddr(t)

			bYAML := fmt.Sprintf(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: a2a-e2e-b
  version: "1.0.0"
  did: %s
sandbox:
  image: curlimages/curl:latest
  memory_mb: 128
  command: ["sh","-c",%q]
  network:
    egress: restricted
capabilities: [external_api]
a2a:
  listen: %q
  peers:
    - name: agent-a
      did: %s
      endpoint: "http://198.51.100.9:7420"
human_gates:
  enabled: false
`, bDID, inboxDrainScript(30), listenAddr, aDID)

			aSend := `
echo "=== A sends to B ==="
RESP=$(curl -s --max-time 25 -X POST -H 'Content-Type: application/json' \
  -d '{"task":"ping"}' "$CONSTLE_A2A_URL/send/agent-b")
echo "A GOT: $RESP"
case "$RESP" in
  *'"pong":true'*) echo "A2A-ROUNDTRIP-OK" ;;
  *) echo "A2A-ROUNDTRIP-FAIL"; exit 1 ;;
esac
`
			aYAML := fmt.Sprintf(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: a2a-e2e-a
  version: "1.0.0"
  did: %s
sandbox:
  image: curlimages/curl:latest
  memory_mb: 128
  command: ["sh","-c",%q]
  network:
    egress: restricted
capabilities: [external_api]
a2a:
  peers:
    - name: agent-b
      did: %s
      endpoint: "http://%s"
human_gates:
  enabled: false
`, aDID, aSend, bDID, listenAddr)

			bPath := writeAgentfile(t, "agent-b.yaml", bYAML)
			aPath := writeAgentfile(t, "agent-a.yaml", aYAML)

			// Process 1: B (the receiver), in the background.
			var bOut bytes.Buffer
			bCmd := exec.Command(bin, "run", "--backend="+name, bPath)
			bCmd.Stdout = &bOut
			bCmd.Stderr = &bOut
			if err := bCmd.Start(); err != nil {
				t.Fatalf("start B: %v", err)
			}
			defer func() {
				bCmd.Process.Kill()
				bCmd.Wait()
			}()

			waitForTCPUp(t, listenAddr, 90*time.Second)

			// Process 2: A (the initiator), run to completion.
			var aOut bytes.Buffer
			aCmd := exec.Command(bin, "run", "--backend="+name, aPath)
			aCmd.Stdout = &aOut
			aCmd.Stderr = &aOut
			aErr := aCmd.Run()

			// B should finish on its own once it has delivered+replied.
			bDone := make(chan error, 1)
			go func() { bDone <- bCmd.Wait() }()
			select {
			case <-bDone:
			case <-time.After(60 * time.Second):
				bCmd.Process.Kill()
			}

			aText, bText := aOut.String(), bOut.String()
			if !strings.Contains(aText, "A2A-ROUNDTRIP-OK") {
				t.Errorf("[%s] A did not complete the round trip (err=%v):\n--- A ---\n%s\n--- B ---\n%s",
					name, aErr, aText, bText)
			}
			if !strings.Contains(bText, "SANDBOX_SAW:") || !strings.Contains(bText, "task") {
				t.Errorf("[%s] B's sandbox did not receive A's call:\n--- B ---\n%s", name, bText)
			}
		})
	}
}

// TestA2AReplayTwoProcess proves the replay guarantee against a REAL running
// receiver process: the exact same validly signed envelope, sent twice in
// quick succession within B's single run, is accepted once and rejected the
// second time by the in-memory msg_id guard — and B's sandbox sees it once.
func TestA2AReplayTwoProcess(t *testing.T) {
	requireE2E(t)

	bin := buildConstle(t)
	aDID := getOrCreateIdentity(t, "a2a-e2e-a")
	bDID := getOrCreateIdentity(t, "a2a-e2e-b")

	// We hold A's key to craft the envelope we will replay.
	aID, err := identity.Load("a2a-e2e-a")
	if err != nil {
		t.Fatalf("load A identity: %v", err)
	}

	for name := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			listenAddr := freeLoopbackAddr(t)

			// A short drain window: long enough to receive the first send and
			// reject the replay, then B exits on its own so its sandbox output
			// is flushed by the CLI (killing constle would skip that flush).
			bYAML := fmt.Sprintf(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: a2a-e2e-b
  version: "1.0.0"
  did: %s
sandbox:
  image: curlimages/curl:latest
  memory_mb: 128
  command: ["sh","-c",%q]
  network:
    egress: restricted
capabilities: [external_api]
a2a:
  listen: %q
  peers:
    - name: agent-a
      did: %s
      endpoint: "http://198.51.100.9:7420"
human_gates:
  enabled: false
`, bDID, inboxDrainScript(12), listenAddr, aDID)

			bPath := writeAgentfile(t, "agent-b.yaml", bYAML)

			var bOut bytes.Buffer
			bCmd := exec.Command(bin, "run", "--backend="+name, bPath)
			bCmd.Stdout = &bOut
			bCmd.Stderr = &bOut
			if err := bCmd.Start(); err != nil {
				t.Fatalf("start B: %v", err)
			}
			defer func() {
				bCmd.Process.Kill()
				bCmd.Wait()
			}()

			waitForTCPUp(t, listenAddr, 90*time.Second)

			// One genuine envelope, signed with A's real key.
			wire, _, err := a2a.Seal(aID, bDID, "", []byte(`{"task":"replay-me"}`))
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			publicURL := "http://" + listenAddr + a2a.CallPath

			// First send: accepted, B's sandbox delivers and replies → 200.
			code1, _ := postWire(t, publicURL, wire)
			if code1 != http.StatusOK {
				t.Fatalf("[%s] first send = HTTP %d, want 200", name, code1)
			}

			// The exact same bytes again: rejected as a replay → 403.
			code2, _ := postWire(t, publicURL, wire)
			if code2 != http.StatusForbidden {
				t.Errorf("[%s] replayed envelope = HTTP %d, want 403", name, code2)
			}

			// Let B finish its short drain window and exit on its own, so the
			// CLI flushes the sandbox output (a kill would skip that flush).
			bDone := make(chan error, 1)
			go func() { bDone <- bCmd.Wait() }()
			select {
			case <-bDone:
			case <-time.After(60 * time.Second):
				bCmd.Process.Kill()
				<-bDone
			}

			bText := bOut.String()
			if n := strings.Count(bText, "SANDBOX_SAW:"); n != 1 {
				t.Errorf("[%s] B's sandbox saw %d messages, want exactly 1 (replay must not deliver twice):\n%s",
					name, n, bText)
			}
			if !strings.Contains(bText, "replay-me") {
				t.Errorf("[%s] B's sandbox did not receive the original call:\n%s", name, bText)
			}
		})
	}
}
