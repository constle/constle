package a2a

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/constle/constle/pkg/manifest"
)

// stubPeer is a fake remote peer host process: it verifies each envelope it
// receives exactly the way a real receiving host would, then answers with
// its own signed response.
type stubPeer struct {
	t      *testing.T
	signer *testSigner
	// respond overrides the default well-behaved response when set.
	respond func(req *Envelope) []byte

	received []*Envelope
}

func (p *stubPeer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		wire, _ := io.ReadAll(r.Body)
		env, err := Open(wire)
		if err != nil {
			p.t.Errorf("stub peer received an unverifiable envelope: %v", err)
			http.Error(w, "bad envelope", http.StatusForbidden)
			return
		}
		p.received = append(p.received, env)

		if p.respond != nil {
			w.Write(p.respond(env))
			return
		}
		respWire, _, err := Seal(p.signer, env.From, env.MsgID, []byte(`{"pong":true}`))
		if err != nil {
			p.t.Fatalf("stub peer cannot seal response: %v", err)
		}
		w.Write(respWire)
	}
}

// newBoundGate builds a Gate for alice with bob as its declared peer at
// endpoint, binds it on loopback, and returns the gate plus its base URL.
func newBoundGate(t *testing.T, alice, bob *testSigner, endpoint string) (*Gate, string) {
	t.Helper()
	m := &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "alice", DID: alice.DID()},
		A2A: manifest.A2A{
			Peers: []manifest.A2APeer{{Name: "bob", DID: bob.DID(), Endpoint: endpoint}},
		},
	}
	g, err := New(m, alice, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { g.Close() })

	port, token, err := g.Bind("testrun01", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	return g, fmt.Sprintf("http://127.0.0.1:%d/%s", port, token)
}

func TestGateOutboundRoundTrip(t *testing.T) {
	alice := newTestSigner(t, 1)
	bob := newTestSigner(t, 2)

	peer := &stubPeer{t: t, signer: bob}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != CallPath {
			t.Errorf("outbound call hit %q, want %q", r.URL.Path, CallPath)
			http.NotFound(w, r)
			return
		}
		peer.handler()(w, r)
	}))
	defer srv.Close()

	_, base := newBoundGate(t, alice, bob, srv.URL)

	resp, err := http.Post(base+"/send/bob", "application/json", strings.NewReader(`{"task":"ping"}`))
	if err != nil {
		t.Fatalf("POST send: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send = HTTP %d: %s", resp.StatusCode, body)
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil || parsed["pong"] != true {
		t.Fatalf("response body = %s, want {\"pong\":true}", body)
	}
	if got := resp.Header.Get("X-Constle-A2A-From"); got != bob.DID() {
		t.Errorf("X-Constle-A2A-From = %q, want bob's DID", got)
	}

	// The peer saw exactly one signed request from alice, addressed to bob.
	if len(peer.received) != 1 {
		t.Fatalf("peer received %d envelopes, want 1", len(peer.received))
	}
	if peer.received[0].From != alice.DID() || peer.received[0].To != bob.DID() {
		t.Errorf("envelope from/to = %s/%s", peer.received[0].From, peer.received[0].To)
	}
	if string(peer.received[0].Body) != `{"task":"ping"}` {
		t.Errorf("envelope body = %s", peer.received[0].Body)
	}
}

func TestGateRejectsUndeclaredPeer(t *testing.T) {
	alice := newTestSigner(t, 1)
	bob := newTestSigner(t, 2)
	_, base := newBoundGate(t, alice, bob, "http://127.0.0.1:1") // endpoint never dialed

	resp, err := http.Post(base+"/send/mallory", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("undeclared peer = HTTP %d, want 403", resp.StatusCode)
	}
}

func TestGateRejectsWrongToken(t *testing.T) {
	alice := newTestSigner(t, 1)
	bob := newTestSigner(t, 2)
	g, _ := newBoundGate(t, alice, bob, "http://127.0.0.1:1")

	resp, err := http.Post(
		fmt.Sprintf("http://127.0.0.1:%d/wrongtoken/send/bob", g.Port()),
		"application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("wrong token = HTTP %d, want 404", resp.StatusCode)
	}
}

func TestGateRejectsNonJSONBody(t *testing.T) {
	alice := newTestSigner(t, 1)
	bob := newTestSigner(t, 2)
	_, base := newBoundGate(t, alice, bob, "http://127.0.0.1:1")

	resp, err := http.Post(base+"/send/bob", "text/plain", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-JSON body = HTTP %d, want 400", resp.StatusCode)
	}
}

func TestGateRejectsResponseFromWrongIdentity(t *testing.T) {
	alice := newTestSigner(t, 1)
	bob := newTestSigner(t, 2)
	mallory := newTestSigner(t, 3)

	// The endpoint answers with a validly signed envelope — but signed by
	// mallory, not the DID declared for bob.
	peer := &stubPeer{t: t, signer: bob, respond: func(req *Envelope) []byte {
		wire, _, err := Seal(mallory, req.From, req.MsgID, []byte(`{"pong":true}`))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		return wire
	}}
	srv := httptest.NewServer(peer.handler())
	defer srv.Close()

	_, base := newBoundGate(t, alice, bob, srv.URL)

	resp, err := http.Post(base+"/send/bob", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("wrong-identity response = HTTP %d (%s), want 502", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "rejected") {
		t.Errorf("error text does not say the response was rejected: %s", body)
	}
}

func TestGateRejectsResponseNotBoundToRequest(t *testing.T) {
	alice := newTestSigner(t, 1)
	bob := newTestSigner(t, 2)

	peer := &stubPeer{t: t, signer: bob, respond: func(req *Envelope) []byte {
		// Correct signer, wrong in_reply_to: a captured response replayed
		// against a different request.
		wire, _, err := Seal(bob, req.From, "someone-elses-msg-id", []byte(`{"pong":true}`))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		return wire
	}}
	srv := httptest.NewServer(peer.handler())
	defer srv.Close()

	_, base := newBoundGate(t, alice, bob, srv.URL)

	resp, err := http.Post(base+"/send/bob", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("unbound response = HTTP %d, want 502", resp.StatusCode)
	}
}

func TestNewRejectsIdentityMismatch(t *testing.T) {
	alice := newTestSigner(t, 1)
	other := newTestSigner(t, 9)
	m := &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "alice", DID: alice.DID()},
	}
	if _, err := New(m, other, nil); err == nil {
		t.Fatal("New accepted a signer that does not match identity.did")
	}
}
