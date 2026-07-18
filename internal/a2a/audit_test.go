package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/pkg/manifest"
)

// newSignedLogger opens a real signed, hash-chained audit logger on a temp
// file — audit completeness is only proven against the production logger,
// not a fake.
func newSignedLogger(t *testing.T, signer *testSigner) (*audit.Logger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.NewSigned(path, signer)
	if err != nil {
		t.Fatalf("NewSigned: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

// a2aEvents reads the log and returns its a2a_* entries in order.
func a2aEvents(t *testing.T, path string) []audit.Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var out []audit.Entry
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		if strings.HasPrefix(string(e.Event), "a2a_") {
			out = append(out, e)
		}
	}
	return out
}

// eventSig compresses an entry to "event/direction[/reason]" for sequence
// assertions.
func eventSig(e audit.Entry) string {
	sig := string(e.Event) + "/" + detailStr(e, "direction")
	if r := detailStr(e, "reason"); r != "" {
		sig += "/" + r
	}
	return sig
}

func detailStr(e audit.Entry, key string) string {
	v, _ := e.Details[key].(string)
	return v
}

// verifyChain asserts the whole log file passes the production verifier.
func verifyChain(t *testing.T, path, did string) {
	t.Helper()
	report, err := audit.VerifyFile(path, did)
	if err != nil {
		t.Fatalf("audit chain broken: %v", err)
	}
	if report.Entries == 0 {
		t.Fatal("audit log is empty")
	}
}

func assertSeq(t *testing.T, entries []audit.Entry, want ...string) {
	t.Helper()
	got := make([]string, len(entries))
	for i, e := range entries {
		got[i] = eventSig(e)
	}
	if len(got) != len(want) {
		t.Fatalf("event sequence = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

// startInboundBob builds bob's gate over a real signed logger with alice
// declared, starts the public listener, and binds the sandbox side.
func startInboundBob(t *testing.T, bob, alice *testSigner) (g *Gate, logPath, publicURL, sandboxURL string) {
	t.Helper()
	logger, path := newSignedLogger(t, bob)
	m := &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "bob", DID: bob.DID()},
		A2A: manifest.A2A{
			Listen: "127.0.0.1:0",
			Peers:  []manifest.A2APeer{{Name: "alice", DID: alice.DID(), Endpoint: "http://127.0.0.1:1"}},
		},
	}
	g, err := New(m, bob, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { g.Close() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if err := g.StartListener(addr); err != nil {
		t.Fatalf("StartListener: %v", err)
	}
	port, token, err := g.Bind("bobrun01", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	waitForListener(t, addr)
	return g, path, "http://" + addr + CallPath, fmt.Sprintf("http://127.0.0.1:%d/%s", port, token)
}

func TestAuditSymmetricRoundTrip(t *testing.T) {
	alice := newTestSigner(t, 1)
	bob := newTestSigner(t, 2)

	_, bobLog, publicURL, bobSandbox := startInboundBob(t, bob, alice)

	// Bob's "agent": drain one call and reply.
	go func() {
		for i := 0; i < 40; i++ {
			resp, err := http.Get(bobSandbox + "/inbox")
			if err != nil {
				return
			}
			if resp.StatusCode == http.StatusOK {
				msgID := resp.Header.Get("X-Constle-A2A-Msg-Id")
				io.ReadAll(resp.Body)
				resp.Body.Close()
				rr, err := http.Post(bobSandbox+"/reply/"+msgID, "application/json",
					strings.NewReader(`{"pong":true}`))
				if err == nil {
					rr.Body.Close()
				}
				return
			}
			resp.Body.Close()
		}
	}()

	// Alice's side: her own gate over her own signed log.
	aliceLogger, aliceLog := newSignedLogger(t, alice)
	mA := &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "alice", DID: alice.DID()},
		A2A: manifest.A2A{
			Peers: []manifest.A2APeer{{Name: "bob", DID: bob.DID(), Endpoint: strings.TrimSuffix(publicURL, CallPath)}},
		},
	}
	gA, err := New(mA, alice, aliceLogger)
	if err != nil {
		t.Fatalf("New alice: %v", err)
	}
	t.Cleanup(func() { gA.Close() })
	port, token, err := gA.Bind("alicerun01", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("Bind alice: %v", err)
	}

	resp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/%s/send/bob", port, token),
		"application/json", strings.NewReader(`{"task":"ping"}`))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send = HTTP %d: %s", resp.StatusCode, body)
	}

	// Alice's log: the full round trip in two symmetric entries.
	aliceEvents := a2aEvents(t, aliceLog)
	assertSeq(t, aliceEvents,
		"a2a_call_sent/request",
		"a2a_call_received/response",
	)
	if sent, recv := aliceEvents[0], aliceEvents[1]; detailStr(sent, "msg_id") != detailStr(recv, "in_reply_to") {
		t.Errorf("alice: received.in_reply_to %q does not close sent.msg_id %q",
			detailStr(recv, "in_reply_to"), detailStr(sent, "msg_id"))
	}
	verifyChain(t, aliceLog, alice.DID())

	// Bob's log: the mirror image.
	bobEvents := a2aEvents(t, bobLog)
	assertSeq(t, bobEvents,
		"a2a_call_received/request",
		"a2a_call_sent/response",
	)
	if recv, sent := bobEvents[0], bobEvents[1]; detailStr(recv, "msg_id") != detailStr(sent, "in_reply_to") {
		t.Errorf("bob: sent.in_reply_to %q does not close received.msg_id %q",
			detailStr(sent, "in_reply_to"), detailStr(recv, "msg_id"))
	}
	verifyChain(t, bobLog, bob.DID())
}

func TestAuditInboundRejectionReasons(t *testing.T) {
	alice := newTestSigner(t, 1)
	bob := newTestSigner(t, 2)
	mallory := newTestSigner(t, 3)
	g, bobLog, publicURL, _ := startInboundBob(t, bob, alice)
	g.replyTimeoutOverride = 300 * time.Millisecond

	post := func(wire []byte) int {
		resp, err := http.Post(publicURL, "application/json", bytes.NewReader(wire))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// unknown_peer: validly signed by an undeclared identity.
	wire, _, err := Seal(mallory, bob.DID(), "", []byte(`{"x":1}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	post(wire)

	// bad_signature: tampered after signing.
	wire, _, err = Seal(alice, bob.DID(), "", []byte(`{"amount":10}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	post(bytes.Replace(wire, []byte(`"amount":10`), []byte(`"amount":99`), 1))

	// malformed: garbage bytes.
	post([]byte("%%%%"))

	// replay: same valid wire twice; the first also produces
	// received/request + rejected/reply_timeout (no agent drains it).
	wire, _, err = Seal(alice, bob.DID(), "", []byte(`{"n":1}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	first := make(chan int, 1)
	go func() { first <- post(wire) }()
	deadline := time.Now().Add(2 * time.Second)
	for len(g.inbox) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	post(wire) // the replay
	if code := <-first; code != http.StatusGatewayTimeout {
		t.Fatalf("first call = HTTP %d, want 504", code)
	}

	events := a2aEvents(t, bobLog)
	wantReasons := map[string]bool{
		"a2a_call_rejected/request/unknown_peer":       false,
		"a2a_call_rejected/request/bad_signature":      false,
		"a2a_call_rejected/request/malformed_envelope": false,
		"a2a_call_rejected/request/replay":             false,
		"a2a_call_received/request":                    false,
		"a2a_call_rejected/response/reply_timeout":     false,
	}
	for _, e := range events {
		if _, tracked := wantReasons[eventSig(e)]; tracked {
			wantReasons[eventSig(e)] = true
		}
		if e.Event == audit.EventA2ACallRejected && detailStr(e, "reason") == "unknown_peer" {
			if detailStr(e, "claimed_did") != mallory.DID() {
				t.Errorf("unknown_peer entry lacks the claimed DID: %v", e.Details)
			}
		}
	}
	for sig, seen := range wantReasons {
		if !seen {
			t.Errorf("expected audit entry %q, not found", sig)
		}
	}
	verifyChain(t, bobLog, bob.DID())
}

func TestAuditTransportFailures(t *testing.T) {
	alice := newTestSigner(t, 1)
	bob := newTestSigner(t, 2)

	t.Run("peer_unreachable", func(t *testing.T) {
		logger, logPath := newSignedLogger(t, alice)
		m := &manifest.AgentManifest{
			Identity: manifest.Identity{Name: "alice", DID: alice.DID()},
			A2A: manifest.A2A{
				Peers: []manifest.A2APeer{{Name: "bob", DID: bob.DID(), Endpoint: "http://127.0.0.1:1"}},
			},
		}
		g, err := New(m, alice, logger)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { g.Close() })
		port, token, err := g.Bind("alicerun02", []string{"127.0.0.1"})
		if err != nil {
			t.Fatalf("Bind: %v", err)
		}
		resp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/%s/send/bob", port, token),
			"application/json", strings.NewReader(`{"x":1}`))
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("send to dead peer = HTTP %d, want 502", resp.StatusCode)
		}

		assertSeq(t, a2aEvents(t, logPath),
			"a2a_call_sent/request",
			"a2a_call_rejected/request/peer_unreachable",
		)
		verifyChain(t, logPath, alice.DID())
	})

	t.Run("peer_http_error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer srv.Close()

		logger, logPath := newSignedLogger(t, alice)
		m := &manifest.AgentManifest{
			Identity: manifest.Identity{Name: "alice", DID: alice.DID()},
			A2A: manifest.A2A{
				Peers: []manifest.A2APeer{{Name: "bob", DID: bob.DID(), Endpoint: srv.URL}},
			},
		}
		g, err := New(m, alice, logger)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { g.Close() })
		port, token, err := g.Bind("alicerun03", []string{"127.0.0.1"})
		if err != nil {
			t.Fatalf("Bind: %v", err)
		}
		resp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/%s/send/bob", port, token),
			"application/json", strings.NewReader(`{"x":1}`))
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		resp.Body.Close()

		events := a2aEvents(t, logPath)
		assertSeq(t, events,
			"a2a_call_sent/request",
			"a2a_call_rejected/response/peer_http_error",
		)
		if detailStr(events[1], "in_reply_to") != detailStr(events[0], "msg_id") {
			t.Errorf("rejection is not bound to the request: %v", events[1].Details)
		}
		verifyChain(t, logPath, alice.DID())
	})

	t.Run("peer_disconnected", func(t *testing.T) {
		g, bobLog, publicURL, _ := startInboundBob(t, bob, alice)

		wire, _, err := Seal(alice, bob.DID(), "", []byte(`{"x":1}`))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, publicURL, bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/json")
		errCh := make(chan error, 1)
		go func() {
			_, err := http.DefaultClient.Do(req)
			errCh <- err
		}()

		// Wait until the call is admitted, then hang up like a dead peer.
		deadline := time.Now().Add(2 * time.Second)
		for len(g.inbox) == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if len(g.inbox) != 1 {
			t.Fatal("call never admitted")
		}
		cancel()
		if err := <-errCh; err == nil {
			t.Fatal("expected the canceled request to error")
		}

		// The disconnect event lands asynchronously with the cancel.
		deadline = time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			events := a2aEvents(t, bobLog)
			if len(events) >= 2 && eventSig(events[len(events)-1]) == "a2a_call_rejected/response/peer_disconnected" {
				verifyChain(t, bobLog, bob.DID())
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("peer_disconnected entry never appeared; events: %v", a2aEvents(t, bobLog))
	})
}
