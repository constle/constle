package sandbox

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/constle/constle/internal/a2a"
	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/pkg/did"
	"github.com/constle/constle/pkg/manifest"
)

// ============================================================
// a2a_conformance_test.go — adversarial A2A enforcement parity
//
// Same rigor and structure as mcp_conformance_test.go, aimed at the inbound
// A2A path. The ground truth is B's SANDBOX: an agent that echoes every
// message body it actually receives from its inbox. Nothing an attacker
// sends may appear there — the proof is the sandbox never seeing it, not
// merely that the host returned an error.
//
// Scenarios, each run against every available backend with identical
// required outcomes:
//
//	reject:  a call signed by an UNDECLARED DID and a TAMPERED call are both
//	         rejected at B's host listener; only a declared peer's genuine
//	         call reaches B's sandbox, which signs a reply.
//	bypass:  an attacker running in its OWN sandbox cannot reach B's inbound
//	         surface (public listener, gateway, or B's sandbox address) by
//	         any network route — every direct attempt fails at the network
//	         layer, and B's sandbox records nothing from it.
//
// Gated behind CONSTLE_E2E=1 because the scenarios start real sandboxes:
//
//	sudo -E CONSTLE_E2E=1 go test ./internal/sandbox/ -run A2A -v
// ============================================================

// a2aSigner is an in-memory a2a.Signer derived from a seed byte — the host
// side of a peer, signing envelopes exactly as identity.Identity would.
type a2aSigner struct {
	didStr string
	priv   ed25519.PrivateKey
}

func newA2ASigner(t *testing.T, seed byte) *a2aSigner {
	t.Helper()
	seedBytes := make([]byte, ed25519.SeedSize)
	seedBytes[0] = seed
	priv := ed25519.NewKeyFromSeed(seedBytes)
	didStr, err := did.FromPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("derive DID: %v", err)
	}
	return &a2aSigner{didStr: didStr, priv: priv}
}

func (s *a2aSigner) DID() string            { return s.didStr }
func (s *a2aSigner) Sign(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }

// freeLoopbackAddr returns a currently-free 127.0.0.1:port for the public
// listener. Grab-and-close leaves a small race, acceptable in tests.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// a2aInboundManifest declares B: identity = bob, one declared peer (alice),
// a public listener on listenAddr, and the given inbox-draining script. The
// network allowlist is empty — the gate route must be the only way out.
func a2aInboundManifest(bobDID, aliceDID, listenAddr, script string) *manifest.AgentManifest {
	return &manifest.AgentManifest{
		APIVersion: "constle.dev/v1alpha1",
		Kind:       "AgentManifest",
		Identity:   manifest.Identity{Name: "a2a-inbound-test", Version: "1.0.0", DID: bobDID},
		Sandbox: manifest.Sandbox{
			Image:    "curlimages/curl:latest",
			MemoryMB: 128,
			Command:  []string{"sh", "-c", script},
			Network:  manifest.Network{Egress: "restricted"},
		},
		Capabilities: []manifest.Capability{manifest.CapExternalAPI},
		A2A: manifest.A2A{
			Listen: listenAddr,
			// alice's endpoint is never dialed here (B only receives); it must
			// merely be a valid, non-allowlisted URL.
			Peers: []manifest.A2APeer{{Name: "alice", DID: aliceDID, Endpoint: "http://198.51.100.7:7420"}},
		},
	}
}

// inboxDrainScript polls the inbox for pollSeconds, echoing "SANDBOX_SAW:
// <body>" for every delivered message and replying to each, then prints
// "SANDBOX_DONE seen=<n>". This is the ground truth for what actually
// crossed into B's sandbox.
func inboxDrainScript(pollSeconds int) string {
	return fmt.Sprintf(`
echo "=== B inbox drain ==="
END=$(( $(date +%%s) + %d ))
SEEN=0
while [ $(date +%%s) -lt $END ]; do
  CODE=$(curl -s -o /tmp/body -D /tmp/hdrs -w '%%{http_code}' --max-time 3 "$CONSTLE_A2A_URL/inbox")
  if [ "$CODE" = "200" ]; then
    SEEN=$((SEEN+1))
    echo "SANDBOX_SAW: $(cat /tmp/body)"
    MID=$(grep -i '^X-Constle-A2A-Msg-Id:' /tmp/hdrs | tr -d '\r' | awk '{print $2}')
    curl -s -o /dev/null -X POST -H 'Content-Type: application/json' \
      -d '{"pong":true}' "$CONSTLE_A2A_URL/reply/$MID"
  fi
done
echo "SANDBOX_DONE seen=$SEEN"
`, pollSeconds)
}

// startA2AGate wires a real A2A gate for m on backend and starts its public
// listener, mirroring the CLI's order: SetA2AGate → Start (binds the gate)
// → StartListener. Returns the running context, the gate, and the audit
// events reader path.
func startA2AGate(t *testing.T, backend SandboxBackend, m *manifest.AgentManifest,
	signer a2a.Signer) (*RunContext, *a2a.Gate, string, func()) {
	t.Helper()

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New(logPath)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}

	gate, err := a2a.New(m, signer, logger)
	if err != nil {
		logger.Close()
		t.Fatalf("a2a.New: %v", err)
	}

	setter, ok := backend.(A2AGateSetter)
	if !ok {
		gate.Close()
		logger.Close()
		t.Fatalf("backend %T does not implement A2AGateSetter", backend)
	}
	setter.SetA2AGate(gate)

	runCtx, err := backend.Start(m)
	if err != nil {
		gate.Close()
		logger.Close()
		t.Fatalf("Start: %v", err)
	}

	if err := gate.StartListener(m.A2A.Listen); err != nil {
		backend.Stop(runCtx)
		gate.Close()
		logger.Close()
		t.Fatalf("StartListener: %v", err)
	}
	waitForTCP(t, m.A2A.Listen, 5*time.Second)

	cleanup := func() {
		backend.Stop(runCtx)
		gate.Close()
		logger.Close()
	}
	return runCtx, gate, logPath, cleanup
}

func waitForTCP(t *testing.T, addr string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s after %s", addr, within)
}

func postWire(t *testing.T, url string, wire []byte) (int, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(string(wire)))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body
}

// TestA2AInboundRejectionNeverReachesSandbox is the core adversarial
// scenario: an undeclared DID and a tampered signature are rejected at B's
// host listener, and only a genuine declared-peer call reaches B's sandbox
// — proven by the sandbox's own output, on both backends identically.
func TestA2AInboundRejectionNeverReachesSandbox(t *testing.T) {
	requireE2E(t)

	type outcome struct {
		LegitDelivered, AttackerNeverSeen, SawExactlyOne bool
	}
	outcomes := map[string]outcome{}

	bob := newA2ASigner(t, 2)
	alice := newA2ASigner(t, 1)
	mallory := newA2ASigner(t, 3)

	for name, backend := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			listenAddr := freeLoopbackAddr(t)
			m := a2aInboundManifest(bob.DID(), alice.DID(), listenAddr, inboxDrainScript(20))

			runCtx, _, logPath, cleanup := startA2AGate(t, backend, m, bob)
			defer cleanup()

			publicURL := "http://" + listenAddr + a2a.CallPath

			// Attack 1: a validly signed envelope from an UNDECLARED identity.
			wire, _, err := a2a.Seal(mallory, bob.DID(), "", []byte(`{"attack":"MALLORY"}`))
			if err != nil {
				t.Fatalf("seal mallory: %v", err)
			}
			if code, _ := postWire(t, publicURL, wire); code != http.StatusForbidden {
				t.Errorf("[%s] undeclared DID = HTTP %d, want 403", name, code)
			}

			// Attack 2: a declared peer's envelope, tampered after signing.
			wire, _, err = a2a.Seal(alice, bob.DID(), "", []byte(`{"legit":"TAMPERED"}`))
			if err != nil {
				t.Fatalf("seal alice(tamper): %v", err)
			}
			tampered := strings.Replace(string(wire), `"legit":"TAMPERED"`, `"legit":"INJECTED"`, 1)
			if code, _ := postWire(t, publicURL, []byte(tampered)); code != http.StatusForbidden {
				t.Errorf("[%s] tampered call = HTTP %d, want 403", name, code)
			}

			// Legit: a genuine call from the declared peer. Blocks until B's
			// sandbox replies through the gate.
			wire, sealed, err := a2a.Seal(alice, bob.DID(), "", []byte(`{"legit":"PINGACCEPT"}`))
			if err != nil {
				t.Fatalf("seal alice: %v", err)
			}
			code, respWire := postWire(t, publicURL, wire)
			if code != http.StatusOK {
				t.Fatalf("[%s] legit call = HTTP %d: %s", name, code, respWire)
			}
			respEnv, err := a2a.Open(respWire)
			if err != nil {
				t.Errorf("[%s] reply not verifiable: %v", name, err)
			} else if respEnv.From != bob.DID() || respEnv.InReplyTo != sealed.MsgID {
				t.Errorf("[%s] reply from/in_reply_to = %s/%s", name, respEnv.From, respEnv.InReplyTo)
			}

			done := make(chan struct{})
			go func() { backend.Wait(runCtx); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Minute):
				backend.Kill(runCtx)
				t.Fatalf("[%s] B did not finish in time", name)
			}

			logs, err := backend.Logs(runCtx)
			if err != nil {
				t.Fatalf("Logs: %v", err)
			}
			out := string(logs)

			o := outcome{
				LegitDelivered:    strings.Contains(out, "SANDBOX_SAW: ") && strings.Contains(out, "PINGACCEPT"),
				AttackerNeverSeen: !strings.Contains(out, "MALLORY") && !strings.Contains(out, "INJECTED"),
				SawExactlyOne:     strings.Count(out, "SANDBOX_SAW:") == 1,
			}
			outcomes[name] = o

			if !o.LegitDelivered {
				t.Errorf("[%s] genuine declared-peer call never reached the sandbox:\n%s", name, out)
			}
			if !o.AttackerNeverSeen {
				t.Errorf("[%s] an attacker payload REACHED the sandbox:\n%s", name, out)
			}
			if !o.SawExactlyOne {
				t.Errorf("[%s] sandbox saw %d messages, want exactly 1:\n%s",
					name, strings.Count(out, "SANDBOX_SAW:"), out)
			}

			events := readA2AEvents(t, logPath, runCtx.RunID)
			if got := countA2AReason(events, "unknown_peer"); got != 1 {
				t.Errorf("[%s] want 1 unknown_peer rejection, got %d", name, got)
			}
			if got := countA2AReason(events, "bad_signature"); got != 1 {
				t.Errorf("[%s] want 1 bad_signature rejection, got %d", name, got)
			}
			if got := countEvents(events, audit.EventA2ACallReceived); got != 1 {
				t.Errorf("[%s] want 1 a2a_call_received, got %d", name, got)
			}
			if got := countEvents(events, audit.EventA2ACallSent); got != 1 {
				t.Errorf("[%s] want 1 a2a_call_sent (response), got %d", name, got)
			}
		})
	}

	if len(outcomes) == 2 && outcomes["docker"] != outcomes["firecracker"] {
		t.Errorf("backends disagree on inbound rejection:\n  docker:      %+v\n  firecracker: %+v",
			outcomes["docker"], outcomes["firecracker"])
	}
}

// readA2AEvents reads the a2a_* audit entries for a run.
func readA2AEvents(t *testing.T, logPath, runID string) []audit.Entry {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var out []audit.Entry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("corrupt audit line %q: %v", line, err)
		}
		if e.RunID == runID && strings.HasPrefix(string(e.Event), "a2a_") {
			out = append(out, e)
		}
	}
	return out
}

func countA2AReason(events []audit.Entry, reason string) int {
	n := 0
	for _, e := range events {
		if e.Event == audit.EventA2ACallRejected {
			if r, _ := e.Details["reason"].(string); r == reason {
				n++
			}
		}
	}
	return n
}

// newBackendLike returns a fresh backend instance of the named kind, so the
// attacker run does not share gate wiring with B's run.
func newBackendLike(t *testing.T, name string) SandboxBackend {
	t.Helper()
	switch name {
	case "docker":
		return &DockerBackend{}
	case "firecracker":
		return &FirecrackerBackend{}
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// bSandboxAddr returns the network address of B's SANDBOX itself (the guest
// / container), the thing an attacker must not be able to reach directly.
func bSandboxAddr(t *testing.T, name string, runCtx *RunContext) string {
	t.Helper()
	switch name {
	case "docker":
		out, err := exec.Command("docker", "inspect", "-f",
			"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
			runCtx.AgentContainerID).Output()
		if err != nil {
			t.Fatalf("docker inspect B's container IP: %v", err)
		}
		return strings.TrimSpace(string(out))
	case "firecracker":
		st, err := readFCState(runCtx.RunID)
		if err != nil {
			t.Fatalf("read B's run state: %v", err)
		}
		// The guest is the other host of the /30: gateway is .base+1, guest
		// .base+2, so the guest's last octet is the gateway's + 1.
		octets := strings.Split(st.GatewayIP, ".")
		last, _ := strconv.Atoi(octets[len(octets)-1])
		octets[len(octets)-1] = strconv.Itoa(last + 1)
		return strings.Join(octets, ".")
	default:
		t.Fatalf("unknown backend %q", name)
		return ""
	}
}

// a2aBypassManifest is the attacker: its own sandbox, egress restricted with
// an empty allowlist, whose script tries to inject an A2A call directly into
// B — at B's sandbox address and B's public listener — by every route. All
// must fail at the network layer. The targets are templated in.
func a2aBypassManifest(bSandbox, bListener string) *manifest.AgentManifest {
	script := fmt.Sprintf(`
echo "=== attacker: direct injection attempts ==="
B_SANDBOX=%q
B_LISTENER=%q

inject() { # $1 = target host:port label, $2 = url
  RESP=$(curl -s --max-time 5 -o /dev/null -w '%%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    -d '{"attack":"DIRECT_INJECT"}' "$2" 2>&1)
  if [ "$RESP" = "200" ]; then
    echo "BYPASS: SUCCEEDED — $1 accepted a direct call ($RESP)"
  else
    echo "BYPASS: FAILED — $1 unreachable/refused ($RESP)"
  fi
}

echo "Attempt 1: B's sandbox directly, via egress proxy"
inject "B-sandbox-proxied" "http://$B_SANDBOX:7423/a2a/v1/call"

echo "Attempt 2: B's sandbox directly, proxy env unset"
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy
inject "B-sandbox-direct" "http://$B_SANDBOX:7423/a2a/v1/call"

echo "Attempt 3: B's public listener directly (host loopback), no proxy"
inject "B-listener-direct" "http://$B_LISTENER/a2a/v1/call"

echo "=== attacker done ==="
`, bSandbox, bListener)

	return &manifest.AgentManifest{
		APIVersion: "constle.dev/v1alpha1",
		Kind:       "AgentManifest",
		Identity:   manifest.Identity{Name: "a2a-attacker", Version: "1.0.0"},
		Sandbox: manifest.Sandbox{
			Image:    "curlimages/curl:latest",
			MemoryMB: 128,
			Command:  []string{"sh", "-c", script},
			Network:  manifest.Network{Egress: "restricted"},
		},
		Capabilities: []manifest.Capability{manifest.CapExternalAPI},
	}
}

// TestA2ADirectSandboxAccessFailsAtNetwork proves the third adversarial
// bullet: an attacker in its OWN sandbox cannot reach B's sandbox or B's
// public listener by any network route — every direct injection fails at
// the network layer, and B's sandbox records nothing from it. Same
// methodology as the existing bypass-test scenarios, applied to the inbound
// A2A surface, on both backends.
func TestA2ADirectSandboxAccessFailsAtNetwork(t *testing.T) {
	requireE2E(t)

	bob := newA2ASigner(t, 2)
	alice := newA2ASigner(t, 1)

	type outcome struct{ AllFailed, NoneSucceeded, SandboxClean bool }
	outcomes := map[string]outcome{}

	for name, backend := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			// B is a real A2A receiver, draining its inbox the whole time so a
			// successful injection WOULD show up as SANDBOX_SAW.
			listenAddr := freeLoopbackAddr(t)
			mB := a2aInboundManifest(bob.DID(), alice.DID(), listenAddr, inboxDrainScript(25))
			bCtx, _, _, bCleanup := startA2AGate(t, backend, mB, bob)
			defer bCleanup()

			bSandbox := bSandboxAddr(t, name, bCtx)
			t.Logf("[%s] B sandbox address: %s, listener: %s", name, bSandbox, listenAddr)

			// The attacker runs in its own sandbox on a fresh backend instance.
			attacker := newBackendLike(t, name)
			mA := a2aBypassManifest(bSandbox, listenAddr)
			aCtx, err := attacker.Start(mA)
			if err != nil {
				t.Fatalf("attacker Start: %v", err)
			}
			defer attacker.Stop(aCtx)

			done := make(chan struct{})
			go func() { attacker.Wait(aCtx); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Minute):
				attacker.Kill(aCtx)
				t.Fatalf("[%s] attacker did not finish", name)
			}

			aLogs, err := attacker.Logs(aCtx)
			if err != nil {
				t.Fatalf("attacker Logs: %v", err)
			}
			aOut := string(aLogs)

			failed := strings.Count(aOut, "BYPASS: FAILED")
			o := outcome{
				AllFailed:     failed >= 3,
				NoneSucceeded: !strings.Contains(aOut, "BYPASS: SUCCEEDED"),
			}

			// Let B finish and confirm its sandbox never saw the attacker.
			bDone := make(chan struct{})
			go func() { backend.Wait(bCtx); close(bDone) }()
			select {
			case <-bDone:
			case <-time.After(3 * time.Minute):
				backend.Kill(bCtx)
				t.Fatalf("[%s] B did not finish", name)
			}
			bLogs, err := backend.Logs(bCtx)
			if err != nil {
				t.Fatalf("B Logs: %v", err)
			}
			o.SandboxClean = !strings.Contains(string(bLogs), "DIRECT_INJECT") &&
				strings.Contains(string(bLogs), "SANDBOX_DONE seen=0")
			outcomes[name] = o

			if o.NoneSucceeded == false {
				t.Errorf("[%s] an attacker reached B directly:\n%s", name, aOut)
			}
			if !o.AllFailed {
				t.Errorf("[%s] want ≥3 failed injection attempts, got %d:\n%s", name, failed, aOut)
			}
			if !o.SandboxClean {
				t.Errorf("[%s] B's sandbox saw the attacker or a message it should not have:\n%s", name, string(bLogs))
			}
		})
	}

	if len(outcomes) == 2 && outcomes["docker"] != outcomes["firecracker"] {
		t.Errorf("backends disagree on direct-access bypass:\n  docker:      %+v\n  firecracker: %+v",
			outcomes["docker"], outcomes["firecracker"])
	}
}
