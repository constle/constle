package mcpgate

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/constle/constle/internal/audit"
)

// TestUpgradeCannotCarryPostHandshakeBytes covers the part of C-35 that the
// handshake tests cannot: bytes sent only after an upstream has accepted an
// HTTP Upgrade. TestUpgradeRequestIsRefused proves the handshake never reaches
// the upstream, and TestUnsolicitedSwitchingProtocolsIsNotSpliced proves an
// unasked-for 101 is not spliced; neither sends a payload from the client
// after a requested 101. Before 383664f the gate forwarded the handshake,
// httputil.ReverseProxy spliced the two connections, and everything the client
// wrote afterwards reached the MCP host raw — a host the sandbox is forbidden
// to reach directly, around the request inspection this gate exists for.
//
// The test speaks raw TCP to the gate so that it controls exactly when the
// payload is written: only after a 101 has been read back. The fixed gate
// answers 400 before the payload is ever sent, and that refusal is held to the
// same three facts TestUpgradeRequestIsRefused checks — the status, an
// upstream that was never called, and an audit event naming the upgrade as
// the reason — so a 400 that came from some other check cannot pass for it.
func TestUpgradeCannotCarryPostHandshakeBytes(t *testing.T) {
	const probe = "C35: POST-UPGRADE BYTES REACHED EGRESS-BLOCKED MCP\n"

	// Everything the upstream observes is reported through this channel
	// rather than through t, because the upstream handler runs on a
	// goroutine that may outlive the test.
	type upstreamOutcome struct {
		payload string
		err     error
	}
	outcome := make(chan upstreamOutcome, 1)

	h := newHarnessWithUpstreamHandler(t, &fixedApprover{decision: DecisionApproved}, "abort", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			outcome <- upstreamOutcome{err: fmt.Errorf("upstream hijack: %w", err)}
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		_, err = rw.WriteString(
			"HTTP/1.1 101 Switching Protocols\r\n" +
				"Connection: Upgrade\r\n" +
				"Upgrade: websocket\r\n\r\n",
		)
		if err == nil {
			err = rw.Flush()
		}
		if err != nil {
			outcome <- upstreamOutcome{err: fmt.Errorf("upstream write 101: %w", err)}
			return
		}

		got := make([]byte, len(probe))
		if _, err := io.ReadFull(rw, got); err != nil {
			outcome <- upstreamOutcome{err: fmt.Errorf("upstream read post-upgrade payload: %w", err)}
			return
		}
		outcome <- upstreamOutcome{payload: string(got)}
	}))

	req, err := http.NewRequest(http.MethodGet, h.baseURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	conn, err := net.Dial("tcp", req.URL.Host)
	if err != nil {
		t.Fatalf("dial gate: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = fmt.Fprintf(conn,
		"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
		req.URL.RequestURI(), req.URL.Host)
	if err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusBadRequest:
		// The refusal the fixed gate gives. It must be the upgrade refusal
		// and nothing else: a 400 from a path or method check would pass a
		// status-only assertion while leaving the upgrade path untested.
		_, _ = io.Copy(io.Discard, resp.Body)
		if got := h.calls.Load(); got != 0 {
			t.Errorf("reached the upstream %d times, want 0", got)
		}
		select {
		case o := <-outcome:
			t.Errorf("upstream observed %+v despite the 400 refusal", o)
		default:
		}
		entries := auditEvents(t, h)
		if len(entries) != 1 {
			t.Fatalf("%d audit events, want exactly 1", len(entries))
		}
		blocked := entries[0]
		if blocked.Event != audit.EventMCPRequestBlocked {
			t.Fatalf("audit event=%q, want %q", blocked.Event, audit.EventMCPRequestBlocked)
		}
		// Keep this hard-coded string deliberately instead of referring to
		// reasonProtocolUpgrade. This test is also overlaid on 383664f^ to prove
		// the regression, and that revision predates the constant, so referring
		// to it would not compile there. Because this expected value is independent
		// of the production constant, changing the production reason makes the
		// current test fail; update the literal only for an intentional audit
		// contract change.
		const wantReason = "the MCP transport defines no protocol upgrade"
		if reason, _ := blocked.Details["reason"].(string); reason != wantReason {
			t.Errorf("reason=%q, want %q", reason, wantReason)
		}
		return
	case http.StatusSwitchingProtocols:
		// The gate spliced the handshake through. What follows shows whether
		// the splice carries bytes, which is the actual asset at stake.
	default:
		t.Fatalf("status=%d, want 400 refusal", resp.StatusCode)
	}

	// Deliberately sent only after the gate returned 101.
	if _, err := io.WriteString(conn, probe); err != nil {
		t.Fatalf("write post-upgrade payload: %v", err)
	}
	select {
	case o := <-outcome:
		if o.err != nil {
			t.Fatalf("gate accepted the upgrade; upstream then failed: %v", o.err)
		}
		if o.payload != probe {
			t.Fatalf("upstream received %q, want %q", o.payload, probe)
		}
		t.Fatalf("post-upgrade payload reached the MCP origin despite empty allowed_hosts")
	case <-time.After(5 * time.Second):
		t.Fatal("gate accepted the upgrade but the post-upgrade probe did not complete")
	}
}
