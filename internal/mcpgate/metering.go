package mcpgate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/spending"
)

// ============================================================
// Spending metering — the gate is the metering point.
//
// The gate already terminates TLS on the agent's behalf as a reverse proxy,
// so it is the one place cost can be measured without widening what Constle
// can see (generic TLS interception of allowed_hosts traffic is rejected as
// an architectural direction — see internal/spending's package doc).
//
// Every tools/call RESPONSE from a priced server is captured while it
// streams to the agent (unbuffered — SSE keeps flowing) and metered once
// complete: the declared usage_path meters are evaluated against the
// response message and the summed cost is charged to the run's Tracker.
//
// Fail closed, in both directions:
//   - a successful (result-carrying) response missing a declared usage
//     value is a METERING FAILURE — the run is killed, because a server
//     that may omit its usage field can zero its own bill (the inverse of
//     the usage-inflation attack);
//   - once the tracker trips (cap crossed or metering failure), the gate
//     rejects every subsequent request outright, so the agent cannot
//     complete another call even before backend.Kill() lands.
//
// Stated limitations (documented, not silent): JSON-RPC error responses
// and non-2xx transport failures are not charged — no result was delivered
// to the agent; and metering trusts the priced server's own usage numbers,
// which caps agent behavior, inflated usage, and buggy servers, but cannot
// catch a server under-reporting its own bill.
// ============================================================

// maxMeterBytes caps how much of a priced response the gate retains for
// metering. A response that exceeds it is unmeterable and fails closed —
// the same principle as maxBodyBytes for requests.
const maxMeterBytes = maxBodyBytes

// meterCtxKey attaches a *meterJob to a proxied request's context so the
// upstream's ModifyResponse hook can find it.
type meterCtxKey struct{}

// meterJob carries one priced tools/call from request inspection to
// response metering.
type meterJob struct {
	gate  *Gate
	up    *upstream
	tool  string
	reqID json.RawMessage
}

// meterResponse is installed as ModifyResponse on priced upstreams: it
// wraps the response body so bytes stream through to the agent while a
// bounded copy is retained, then meters once the body is fully read (or
// closed early — the remainder is drained so an agent aborting its read
// cannot dodge the charge).
func meterResponse(resp *http.Response) error {
	job, _ := resp.Request.Context().Value(meterCtxKey{}).(*meterJob)
	if job == nil {
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Transport-level failure: no JSON-RPC result was delivered, so
		// there is nothing to charge.
		return nil
	}

	resp.Body = &meterBody{rc: resp.Body, job: job, contentType: resp.Header.Get("Content-Type")}
	return nil
}

// meterBody tees a priced response into a bounded buffer while the agent
// reads it, and triggers metering exactly once when the stream ends.
type meterBody struct {
	rc          io.ReadCloser
	job         *meterJob
	contentType string

	mu       sync.Mutex
	buf      bytes.Buffer
	overflow bool
	metered  bool
}

func (b *meterBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.keep(p[:n])
	}
	if err == io.EOF {
		b.finish()
	}
	return n, err
}

// Close drains whatever the agent did not read (bounded) before metering:
// an agent that aborts mid-response must still be charged for it.
func (b *meterBody) Close() error {
	b.mu.Lock()
	metered := b.metered
	b.mu.Unlock()
	if !metered {
		rest, err := io.ReadAll(io.LimitReader(b.rc, maxMeterBytes+1))
		if len(rest) > 0 {
			b.keep(rest)
		}
		if err != nil {
			b.job.gate.meterFailure(b.job, fmt.Sprintf("response truncated before it could be metered: %v", err))
			b.mu.Lock()
			b.metered = true
			b.mu.Unlock()
		} else {
			b.finish()
		}
	}
	return b.rc.Close()
}

func (b *meterBody) keep(p []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.overflow {
		return
	}
	if b.buf.Len()+len(p) > maxMeterBytes {
		b.overflow = true
		return
	}
	b.buf.Write(p)
}

func (b *meterBody) finish() {
	b.mu.Lock()
	if b.metered {
		b.mu.Unlock()
		return
	}
	b.metered = true
	overflow := b.overflow
	body := append([]byte(nil), b.buf.Bytes()...)
	b.mu.Unlock()

	if overflow {
		b.job.gate.meterFailure(b.job, fmt.Sprintf("response larger than %d bytes cannot be metered", maxMeterBytes))
		return
	}
	b.job.gate.meterCompleted(b.job, body, b.contentType)
}

// meterCompleted parses the full response of one priced tools/call and
// charges it. Any shape we cannot positively charge is a metering failure.
func (g *Gate) meterCompleted(job *meterJob, body []byte, contentType string) {
	msgBytes, err := responseMessage(body, contentType, job.reqID)
	if err != nil {
		g.meterFailure(job, err.Error())
		return
	}

	var probe struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(msgBytes, &probe); err != nil {
		g.meterFailure(job, fmt.Sprintf("response message is not valid JSON: %v", err))
		return
	}
	if len(probe.Result) == 0 {
		// A JSON-RPC error delivered no result — nothing to charge.
		return
	}

	cost, err := spending.MeterResponse(msgBytes, job.up.meters)
	if err != nil {
		g.meterFailure(job, err.Error())
		return
	}
	g.charge(job, cost)
}

// charge applies one metered cost to the run's tracker and enforces the
// outcome: a one-time warning event at the alert threshold, and on a cap
// violation a limit event, the gate trip, and the run kill.
func (g *Gate) charge(job *meterJob, cost spending.MicroCents) {
	res, err := g.tracker.Charge(g.currentRunID(), job.up.id, cost)
	if err != nil {
		// A charge we could compute but not durably record is as fatal as
		// one we could not compute: never let spend leak past the ledger.
		g.meterFailure(job, fmt.Sprintf("cannot record charge: %v", err))
		return
	}

	limits := g.tracker.Limits()

	if res.WarnCrossed {
		g.log(audit.EventSpendingLimit, map[string]any{
			"severity":        "warning",
			"threshold_pct":   limits.WarnAtPctOfDaily,
			"day_total_usd":   res.DayTotal.USD(),
			"max_per_day_usd": limits.PerDay.USD(),
			"server":          job.up.id,
			"tool":            job.tool,
			"charge_usd":      res.Amount.USD(),
			"run_total_usd":   res.RunTotal.USD(),
		})
	}

	if res.NewlyTripped {
		details := map[string]any{
			"severity":      "limit",
			"limit":         string(res.Violation),
			"server":        job.up.id,
			"tool":          job.tool,
			"charge_usd":    res.Amount.USD(),
			"run_total_usd": res.RunTotal.USD(),
		}
		switch res.Violation {
		case spending.ViolationPerRun:
			details["max_per_run_usd"] = limits.PerRun.USD()
		case spending.ViolationPerDay:
			details["max_per_day_usd"] = limits.PerDay.USD()
			details["day_total_usd"] = res.DayTotal.USD()
		}
		g.log(audit.EventSpendingLimit, details)
	}

	if res.Violation != spending.ViolationNone {
		g.fireSpendKill()
	}
}

// meterFailure records an unmeterable priced response and fails closed:
// the tracker trips (all further calls are rejected) and the run is killed.
func (g *Gate) meterFailure(job *meterJob, reason string) {
	g.log(audit.EventSpendingLimit, map[string]any{
		"severity": "metering_failure",
		"server":   job.up.id,
		"tool":     job.tool,
		"reason":   reason,
	})
	g.tracker.Trip(spending.ViolationMetering)
	g.fireSpendKill()
}

// responseMessage extracts the JSON-RPC response message for reqID from a
// completed tools/call response body — either a plain JSON body or a
// text/event-stream (streamable HTTP). Server-side notifications and
// requests inside an SSE stream are skipped; only the response message
// (id match, carrying result or error) is metered.
func responseMessage(body []byte, contentType string, reqID json.RawMessage) ([]byte, error) {
	mediaType := contentType
	if mt, _, err := mime.ParseMediaType(contentType); err == nil {
		mediaType = mt
	}

	if !strings.EqualFold(mediaType, "text/event-stream") {
		if len(bytes.TrimSpace(body)) == 0 {
			return nil, fmt.Errorf("empty response body — no response message to meter")
		}
		return body, nil
	}

	var exact []byte
	var candidates [][]byte
	for _, data := range sseDataPayloads(body) {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if len(msg.Result) == 0 && len(msg.Error) == 0 {
			continue // notification or server-side request
		}
		if jsonEqual(msg.ID, reqID) {
			exact = data
			break
		}
		candidates = append(candidates, data)
	}

	switch {
	case exact != nil:
		return exact, nil
	case len(candidates) == 1:
		// Sole response in the stream: meter it even if the server
		// reformatted the id.
		return candidates[0], nil
	case len(candidates) == 0:
		return nil, fmt.Errorf("SSE stream ended without a response message to meter")
	default:
		return nil, fmt.Errorf("SSE stream has %d response messages, none matching the request id — cannot attribute cost", len(candidates))
	}
}

// sseDataPayloads splits a text/event-stream body into the concatenated
// data payloads of each event, per the SSE framing rules (multiple data:
// lines join with \n; a blank line ends an event).
func sseDataPayloads(body []byte) [][]byte {
	var payloads [][]byte
	var data []string

	flush := func() {
		if len(data) > 0 {
			payloads = append(payloads, []byte(strings.Join(data, "\n")))
			data = nil
		}
	}

	for _, rawLine := range strings.Split(string(body), "\n") {
		line := strings.TrimSuffix(rawLine, "\r")
		if line == "" {
			flush()
			continue
		}
		if rest, ok := strings.CutPrefix(line, "data:"); ok {
			data = append(data, strings.TrimPrefix(rest, " "))
		}
	}
	flush()
	return payloads
}

// jsonEqual compares two raw JSON values for equality after compaction.
func jsonEqual(a, b json.RawMessage) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	var ca, cb bytes.Buffer
	if json.Compact(&ca, a) != nil || json.Compact(&cb, b) != nil {
		return false
	}
	return bytes.Equal(ca.Bytes(), cb.Bytes())
}

// currentRunID reads the run id under the gate mutex.
func (g *Gate) currentRunID() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.runID
}

// fireSpendKill invokes the kill callback installed by the CLI. Like the
// gate-timeout abort, the callback is read at fire time, not at charge
// entry, so a violation racing ahead of Start()'s return still kills once
// installed — and every later rejected call re-fires it (idempotent via
// the CLI's sync.Once), so a kill can never be lost to that race.
func (g *Gate) fireSpendKill() {
	g.mu.Lock()
	kill := g.spendKill
	g.mu.Unlock()
	if kill != nil {
		kill()
	}
}

// SetSpendKill installs the callback that terminates the run when a
// spending limit is crossed or a priced response cannot be metered.
// Installed by the CLI right after the sandbox starts, alongside
// SetAbortRun.
func (g *Gate) SetSpendKill(kill func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.spendKill = kill
}
