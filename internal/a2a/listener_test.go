package a2a

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/constle/constle/pkg/manifest"
)

// newInboundGate builds bob's gate with alice declared as a peer, starts
// the public listener on an ephemeral loopback port, binds the
// sandbox-facing gate, and returns (gate, publicURL, sandboxBaseURL).
func newInboundGate(t *testing.T, bob, alice *testSigner) (*Gate, string, string) {
	t.Helper()
	m := &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "bob", DID: bob.DID()},
		A2A: manifest.A2A{
			Listen: "127.0.0.1:0",
			Peers:  []manifest.A2APeer{{Name: "alice", DID: alice.DID(), Endpoint: "http://127.0.0.1:1"}},
		},
	}
	g, err := New(m, bob, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { g.Close() })
	g.replyTimeoutOverride = 2 * time.Second
	g.pollTimeoutOverride = 200 * time.Millisecond

	// Ephemeral public port: bind ourselves, pass the resolved address.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if err := g.StartListener(addr); err != nil {
		t.Fatalf("StartListener: %v", err)
	}

	port, token, err := g.Bind("testrun02", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}

	waitForListener(t, addr)
	return g, "http://" + addr + CallPath, fmt.Sprintf("http://127.0.0.1:%d/%s", port, token)
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("public listener on %s never came up", addr)
}

// drainInbox asserts the agent-visible inbox state: wantEmpty means the
// long-poll must close with 204 and nothing may be pending.
func assertInboxEmpty(t *testing.T, g *Gate, sandboxURL string) {
	t.Helper()
	resp, err := http.Get(sandboxURL + "/inbox")
	if err != nil {
		t.Fatalf("GET inbox: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("inbox = HTTP %d, want 204 (empty)", resp.StatusCode)
	}
	if n := len(g.inbox); n != 0 {
		t.Fatalf("inbox holds %d calls, want 0", n)
	}
}

func TestInboundFullFlow(t *testing.T) {
	bob := newTestSigner(t, 2)
	alice := newTestSigner(t, 1)
	_, publicURL, sandboxURL := newInboundGate(t, bob, alice)

	// The "agent" side: long-poll, then reply — concurrently with the call.
	agentDone := make(chan error, 1)
	go func() {
		agentDone <- func() error {
			var resp *http.Response
			var err error
			for i := 0; i < 20; i++ { // re-poll across empty windows
				resp, err = http.Get(sandboxURL + "/inbox")
				if err != nil {
					return err
				}
				if resp.StatusCode == http.StatusOK {
					break
				}
				resp.Body.Close()
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("inbox never delivered (last HTTP %d)", resp.StatusCode)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != `{"task":"ping"}` {
				return fmt.Errorf("delivered body = %s", body)
			}
			if from := resp.Header.Get("X-Constle-A2A-From"); from != alice.DID() {
				return fmt.Errorf("X-Constle-A2A-From = %q", from)
			}
			if peer := resp.Header.Get("X-Constle-A2A-Peer"); peer != "alice" {
				return fmt.Errorf("X-Constle-A2A-Peer = %q", peer)
			}
			msgID := resp.Header.Get("X-Constle-A2A-Msg-Id")

			rr, err := http.Post(sandboxURL+"/reply/"+msgID, "application/json",
				strings.NewReader(`{"pong":true}`))
			if err != nil {
				return err
			}
			rr.Body.Close()
			if rr.StatusCode != http.StatusNoContent {
				return fmt.Errorf("reply = HTTP %d", rr.StatusCode)
			}
			return nil
		}()
	}()

	// The "peer" side: alice signs and calls bob's public listener.
	wire, sealed, err := Seal(alice, bob.DID(), "", []byte(`{"task":"ping"}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	resp, err := http.Post(publicURL, "application/json", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("POST public: %v", err)
	}
	defer resp.Body.Close()
	respWire, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public call = HTTP %d: %s", resp.StatusCode, respWire)
	}

	if err := <-agentDone; err != nil {
		t.Fatalf("agent side: %v", err)
	}

	// The response is a real envelope signed by bob, addressed to alice,
	// bound to the request.
	env, err := Open(respWire)
	if err != nil {
		t.Fatalf("Open response: %v", err)
	}
	if env.From != bob.DID() || env.To != alice.DID() || env.InReplyTo != sealed.MsgID {
		t.Fatalf("response from/to/in_reply_to = %s/%s/%s", env.From, env.To, env.InReplyTo)
	}
	if string(env.Body) != `{"pong":true}` {
		t.Fatalf("response body = %s", env.Body)
	}
}

func TestInboundUnknownPeerNeverReachesInbox(t *testing.T) {
	bob := newTestSigner(t, 2)
	alice := newTestSigner(t, 1)
	mallory := newTestSigner(t, 3)
	g, publicURL, sandboxURL := newInboundGate(t, bob, alice)

	// Mallory's envelope is validly signed — by an undeclared identity.
	wire, _, err := Seal(mallory, bob.DID(), "", []byte(`{"task":"steal"}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	resp, err := http.Post(publicURL, "application/json", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("POST public: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown peer = HTTP %d, want 403", resp.StatusCode)
	}

	// The decisive check: the sandbox side never sees anything.
	assertInboxEmpty(t, g, sandboxURL)
}

func TestInboundForgedAndTamperedRejected(t *testing.T) {
	bob := newTestSigner(t, 2)
	alice := newTestSigner(t, 1)
	mallory := newTestSigner(t, 3)
	g, publicURL, sandboxURL := newInboundGate(t, bob, alice)

	valid, _, err := Seal(alice, bob.DID(), "", []byte(`{"amount":10}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for name, wire := range map[string][]byte{
		"tampered body": bytes.Replace(valid, []byte(`"amount":10`), []byte(`"amount":99`), 1),
		"forged sender": func() []byte {
			w, _, err := Seal(mallory, bob.DID(), "", []byte(`{"x":1}`))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			return bytes.Replace(w, []byte(mallory.DID()), []byte(alice.DID()), 1)
		}(),
	} {
		resp, err := http.Post(publicURL, "application/json", bytes.NewReader(wire))
		if err != nil {
			t.Fatalf("%s: POST: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s = HTTP %d, want 403", name, resp.StatusCode)
		}
	}
	assertInboxEmpty(t, g, sandboxURL)
}

func TestInboundGarbageLeavesListenerAlive(t *testing.T) {
	bob := newTestSigner(t, 2)
	alice := newTestSigner(t, 1)
	g, publicURL, sandboxURL := newInboundGate(t, bob, alice)

	for _, garbage := range []string{"", "%%%%", "[]", `{"from":`, strings.Repeat("x", 4096)} {
		resp, err := http.Post(publicURL, "application/json", strings.NewReader(garbage))
		if err != nil {
			t.Fatalf("garbage POST failed at transport level: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("garbage %q = HTTP %d, want 403", garbage[:min(len(garbage), 12)], resp.StatusCode)
		}
	}

	// Wrong path / wrong method: flat 404.
	resp, err := http.Get(publicURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET on call path = HTTP %d, want 404", resp.StatusCode)
	}

	assertInboxEmpty(t, g, sandboxURL)

	// The listener is still alive and still accepts a valid call afterwards.
	wire, _, err := Seal(alice, bob.DID(), "", []byte(`{"ok":1}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	done := make(chan int, 1)
	go func() {
		resp, err := http.Post(publicURL, "application/json", bytes.NewReader(wire))
		if err != nil {
			done <- -1
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	// No agent replies — expect the reply timeout (504), which proves the
	// call passed verification and was parked, i.e. the server survived.
	if code := <-done; code != http.StatusGatewayTimeout {
		t.Fatalf("valid call after garbage = HTTP %d, want 504", code)
	}
}

func TestInboundOversizedBodyCappedBeforeParse(t *testing.T) {
	bob := newTestSigner(t, 2)
	alice := newTestSigner(t, 1)
	g, publicURL, sandboxURL := newInboundGate(t, bob, alice)

	// One byte over the cap, not even JSON — must be rejected on size alone.
	oversized := io.MultiReader(
		strings.NewReader(`{"from":"`),
		&zeroReader{n: maxBodyBytes + 1},
	)
	resp, err := http.Post(publicURL, "application/json", oversized)
	if err != nil {
		// The server may cut the connection mid-upload once the cap is hit;
		// either a clean 413 or a transport error is acceptable — a hang or
		// crash is not.
		t.Logf("oversized upload ended with transport error (acceptable): %v", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized body = HTTP %d, want 413", resp.StatusCode)
		}
	}
	assertInboxEmpty(t, g, sandboxURL)
}

// zeroReader yields n zero bytes.
type zeroReader struct{ n int }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	if len(p) > z.n {
		p = p[:z.n]
	}
	for i := range p {
		p[i] = 0
	}
	z.n -= len(p)
	return len(p), nil
}

func TestInboundReplayRejected(t *testing.T) {
	bob := newTestSigner(t, 2)
	alice := newTestSigner(t, 1)
	g, publicURL, sandboxURL := newInboundGate(t, bob, alice)

	wire, _, err := Seal(alice, bob.DID(), "", []byte(`{"n":1}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// First delivery parks the call (no agent -> it will time out later);
	// fire it in the background.
	first := make(chan int, 1)
	go func() {
		resp, err := http.Post(publicURL, "application/json", bytes.NewReader(wire))
		if err != nil {
			first <- -1
			return
		}
		resp.Body.Close()
		first <- resp.StatusCode
	}()

	// Wait until the first envelope is actually admitted.
	deadline := time.Now().Add(2 * time.Second)
	for len(g.inbox) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(g.inbox) != 1 {
		t.Fatal("first envelope never reached the inbox")
	}

	// The exact same validly signed bytes again, within the same run.
	resp, err := http.Post(publicURL, "application/json", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("replay POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("replayed envelope = HTTP %d, want 403", resp.StatusCode)
	}
	if len(g.inbox) != 1 {
		t.Fatalf("replay reached the inbox (len=%d)", len(g.inbox))
	}

	// Drain: the one delivered call is the original.
	resp, err = http.Get(sandboxURL + "/inbox")
	if err != nil {
		t.Fatalf("GET inbox: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inbox = HTTP %d, want 200", resp.StatusCode)
	}
	if code := <-first; code != http.StatusGatewayTimeout {
		t.Fatalf("first (unanswered) call = HTTP %d, want 504", code)
	}
}

// fillPeerQuota fires quota-many valid calls from signer without draining,
// and waits until they are all admitted.
func fillPeerQuota(t *testing.T, g *Gate, publicURL string, from *testSigner, to string) {
	t.Helper()
	before := len(g.inbox)
	for i := 0; i < perPeerInboxCapacity; i++ {
		wire, _, err := Seal(from, to, "", []byte(fmt.Sprintf(`{"n":%d}`, i)))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		go func() {
			resp, err := http.Post(publicURL, "application/json", bytes.NewReader(wire))
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(g.inbox) < before+perPeerInboxCapacity && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(g.inbox); got != before+perPeerInboxCapacity {
		t.Fatalf("inbox holds %d, want %d", got, before+perPeerInboxCapacity)
	}
}

func TestInboundInboxFullShedsLoad(t *testing.T) {
	bob := newTestSigner(t, 2)
	alice := newTestSigner(t, 1)
	g, publicURL, _ := newInboundGate(t, bob, alice)

	fillPeerQuota(t, g, publicURL, alice, bob.DID())

	// One more verified call: shed with 503, not queued, not crashed.
	wire, _, err := Seal(alice, bob.DID(), "", []byte(`{"overflow":true}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	resp, err := http.Post(publicURL, "application/json", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("overflow POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("overflow call = HTTP %d, want 503", resp.StatusCode)
	}
	if len(g.inbox) != perPeerInboxCapacity {
		t.Fatalf("overflow was queued anyway (len=%d)", len(g.inbox))
	}
}

func TestInboxIsolationBetweenPeers(t *testing.T) {
	// The inbox quota is per peer: a noisy but fully authenticated peer
	// (alice) filling her own quota must not cause an unrelated declared
	// peer (carol) to be shed.
	bob := newTestSigner(t, 2)
	alice := newTestSigner(t, 1)
	carol := newTestSigner(t, 4)

	m := &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "bob", DID: bob.DID()},
		A2A: manifest.A2A{
			Listen: "127.0.0.1:0",
			Peers: []manifest.A2APeer{
				{Name: "alice", DID: alice.DID(), Endpoint: "http://127.0.0.1:1"},
				{Name: "carol", DID: carol.DID(), Endpoint: "http://127.0.0.1:2"},
			},
		},
	}
	g, err := New(m, bob, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { g.Close() })
	g.replyTimeoutOverride = 500 * time.Millisecond

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if err := g.StartListener(addr); err != nil {
		t.Fatalf("StartListener: %v", err)
	}
	waitForListener(t, addr)
	publicURL := "http://" + addr + CallPath

	// Alice floods her whole quota; nothing drains it.
	fillPeerQuota(t, g, publicURL, alice, bob.DID())

	// Alice's next call is shed...
	wire, _, err := Seal(alice, bob.DID(), "", []byte(`{"noise":true}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	resp, err := http.Post(publicURL, "application/json", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("alice over quota = HTTP %d, want 503", resp.StatusCode)
	}

	// ...but carol's call is still admitted: it parks awaiting the agent
	// (504 after the shortened reply timeout), never 503.
	wire, _, err = Seal(carol, bob.DID(), "", []byte(`{"important":true}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	resp, err = http.Post(publicURL, "application/json", bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("carol POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Fatal("carol was shed because of alice's noise — quota is not per-peer")
	}
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("carol = HTTP %d, want 504 (admitted, unanswered)", resp.StatusCode)
	}
	if got := len(g.inbox); got != perPeerInboxCapacity+1 {
		t.Fatalf("inbox holds %d, want %d (alice's quota + carol's call)", got, perPeerInboxCapacity+1)
	}
}

func TestReplyToUnknownMsgID(t *testing.T) {
	bob := newTestSigner(t, 2)
	alice := newTestSigner(t, 1)
	_, _, sandboxURL := newInboundGate(t, bob, alice)

	resp, err := http.Post(sandboxURL+"/reply/nonexistent", "application/json",
		strings.NewReader(`{"pong":true}`))
	if err != nil {
		t.Fatalf("POST reply: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("reply to unknown msg_id = HTTP %d, want 404", resp.StatusCode)
	}
}
