package mcpgate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/constle/constle/pkg/manifest"
)

// TestNewWebhookNotifierIgnoresDisarmedGates: with human_gates.enabled false
// no gate ever triggers, so there is nothing to notify about. Resolving the
// notify block anyway warned that "gate events will only be visible on this
// terminal" — which reads as enforcement having moved somewhere local, when in
// fact no gate is going to fire at all. That is the same false assurance the
// gate reporting was fixed for, reached by a different path.
func TestNewWebhookNotifierIgnoresDisarmedGates(t *testing.T) {
	gates := manifest.HumanGates{
		Enabled:            false,
		RequireApprovalFor: []string{"send_email"},
		Notify: []manifest.NotifyChannel{
			{Channel: "webhook", URLSecretRef: "CONSTLE_TEST_GATE_WEBHOOK"},
		},
	}

	var out bytes.Buffer
	if wn := NewWebhookNotifier(gates, &out); wn != nil {
		t.Errorf("built a notifier for a gate that never triggers: %+v", wn)
	}
	if out.Len() != 0 {
		t.Errorf("warned about a webhook for a disarmed gate: %q", out.String())
	}
}

// TestNewWebhookNotifierWarnsOnUnsetEnvWhenArmed is the other half: with the
// switch on, an unresolvable webhook URL is a real gap and must still be said
// out loud.
func TestNewWebhookNotifierWarnsOnUnsetEnvWhenArmed(t *testing.T) {
	gates := manifest.HumanGates{
		Enabled:            true,
		RequireApprovalFor: []string{"send_email"},
		Notify: []manifest.NotifyChannel{
			{Channel: "webhook", URLSecretRef: "CONSTLE_TEST_GATE_WEBHOOK"},
		},
	}

	var out bytes.Buffer
	if wn := NewWebhookNotifier(gates, &out); wn != nil {
		t.Errorf("notifier = %+v, want nil when the env var is unset", wn)
	}
	if !strings.Contains(out.String(), "CONSTLE_TEST_GATE_WEBHOOK") {
		t.Errorf("want a warning naming the unset env var, got: %q", out.String())
	}
}

// TestNewWebhookNotifierResolvesWhenArmed proves the guard did not disable the
// notifier outright.
func TestNewWebhookNotifierResolvesWhenArmed(t *testing.T) {
	t.Setenv("CONSTLE_TEST_GATE_WEBHOOK", "https://gate.example.com/hook")

	gates := manifest.HumanGates{
		Enabled:            true,
		RequireApprovalFor: []string{"send_email"},
		Notify: []manifest.NotifyChannel{
			{Channel: "webhook", URLSecretRef: "CONSTLE_TEST_GATE_WEBHOOK"},
		},
	}

	var out bytes.Buffer
	wn := NewWebhookNotifier(gates, &out)
	if wn == nil {
		t.Fatal("notifier = nil, want a notifier for an armed gate with a resolved URL")
	}
	if len(wn.URLs) != 1 || wn.URLs[0] != "https://gate.example.com/hook" {
		t.Errorf("URLs = %v, want the resolved webhook", wn.URLs)
	}
	if out.Len() != 0 {
		t.Errorf("unexpected warning: %q", out.String())
	}
}

// rawStatusServer answers one request with a status line written by hand, so
// the test controls the HTTP reason phrase. net/http's own server always
// writes the canonical text for a status code and cannot express this.
//
// The reason phrase cannot carry CR or LF — those end the status line — but
// ESC is legal there, and ESC is the byte that matters.
func rawStatusServer(t *testing.T, statusLine string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Read the request far enough to be a well-behaved peer; the body
		// length does not matter because the connection is closed after.
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(conn,
			statusLine+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()

	return "http:" + "//" + ln.Addr().String()
}

// syncBuf collects output written from the notifier's delivery goroutines and
// signals when something lands.
type syncBuf struct {
	mu    sync.Mutex
	b     bytes.Buffer
	wrote chan struct{}
}

func newSyncBuf() *syncBuf { return &syncBuf{wrote: make(chan struct{}, 1)} }

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.b.Write(p)
	select {
	case s.wrote <- struct{}{}:
	default:
	}
	return n, err
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuf) await(t *testing.T) string {
	t.Helper()
	select {
	case <-s.wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("no warning was written within 5s")
	}
	return s.String()
}

// TestWebhookStatusCannotDriveTheTerminal covers F94.
//
// The reason phrase of an HTTP response is chosen by the remote endpoint and
// passed through verbatim: net/http validates only that the status code is
// three digits (see ReadResponse), and ESC is legal in the rest of the status
// line. constle printed resp.Status with %s onto the very writer the human
// gate draws its approval prompt on, moments before the prompt appears — so a
// decision endpoint could erase the tool call an operator was about to
// approve, or ask the terminal a question whose answer is typed into the
// stdin that collects their answer.
func TestWebhookStatusCannotDriveTheTerminal(t *testing.T) {
	const hostile = "\x1b[2J\x1b[H\x1b[6nEVERYTHING IS FINE"
	url := rawStatusServer(t, "HTTP/1.1 500 "+hostile)

	// Premise first: a test that found no ESC because Go had already removed
	// it would pass without proving anything.
	premiseURL := rawStatusServer(t, "HTTP/1.1 500 "+hostile)
	resp, err := http.Get(premiseURL) //nolint:noctx // fixed local test server
	if err != nil {
		t.Fatalf("premise request: %v", err)
	}
	_ = resp.Body.Close()
	if !strings.ContainsRune(resp.Status, 0x1B) {
		t.Fatalf("premise wrong: net/http stripped the reason phrase, got %q", resp.Status)
	}

	out := newSyncBuf()
	n := &WebhookNotifier{URLs: []string{url}, Out: out}
	n.NotifyTriggered(Request{
		RunID:     "run-1",
		AgentName: "agent",
		ServerID:  "srv",
		Tool:      "send_email",
		Arguments: json.RawMessage(`{"to":"a@b.example"}`),
	})

	got := out.await(t)

	for _, bad := range []rune{0x1B, 0x0D} {
		if strings.ContainsRune(got, bad) {
			t.Errorf("%U from the endpoint's reason phrase reached the terminal: %q", bad, got)
		}
	}
	if !strings.Contains(got, "answered") {
		t.Errorf("the warning itself went missing: %q", got)
	}
	// Escaped rather than dropped: the operator can still see what came back.
	if !strings.Contains(got, `\u001B[2J`) {
		t.Errorf("the reason phrase was hidden rather than escaped: %q", got)
	}
	// One line: the endpoint cannot add a line that reads as constle's.
	if strings.Count(got, "\n") != 1 {
		t.Errorf("the warning spans %d lines, want 1: %q", strings.Count(got, "\n"), got)
	}
}

// TestUnsetNotifyEnvWarningCannotForgeALine covers the other untrusted string
// on this stream. url_secret_ref is validated only for being non-empty, and
// the warning fires on any machine that does not have the operator's secret
// set — so an Agentfile alone puts its text on the terminal.
//
// The gate is armed deliberately, and must stay that way: NewWebhookNotifier
// returns before resolving anything when it is not (see
// TestNewWebhookNotifierIgnoresDisarmedGates above), so a fixture without
// Enabled never reaches the warning this test exists to check, and would
// assert over an empty string instead.
func TestUnsetNotifyEnvWarningCannotForgeALine(t *testing.T) {
	out := newSyncBuf()

	gates := manifest.HumanGates{
		Enabled:            true,
		RequireApprovalFor: []string{"send_email"},
		Notify: []manifest.NotifyChannel{{
			Channel:      "webhook",
			URLSecretRef: "UNSET\x1b[2K\n⏸  human gate: approved",
		}},
	}
	if n := NewWebhookNotifier(gates, out); n != nil {
		t.Fatal("an unset env var should configure no webhook")
	}

	got := out.String()
	// That the warning fired at all comes first, so a fixture that stops
	// reaching it fails as that rather than as a shape mismatch over nothing.
	if !strings.Contains(got, "is not set") {
		t.Fatalf("the unset-env warning never fired, so nothing below is tested: %q", got)
	}
	for _, bad := range []rune{0x1B, 0x0D} {
		if strings.ContainsRune(got, bad) {
			t.Errorf("%U reached the terminal: %q", bad, got)
		}
	}
	if strings.Count(got, "\n") != 1 {
		t.Errorf("an Agentfile field forged a line: %q", got)
	}
}
