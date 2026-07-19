package mcpgate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/spending"
	"github.com/constle/constle/pkg/manifest"
)

// meterHarness bundles a bound gate with a priced upstream whose responses
// the test scripts per call.
type meterHarness struct {
	gate    *Gate
	tracker *spending.Tracker
	calls   *atomic.Int64
	// respond is swapped by tests to script the upstream's next responses.
	respond atomic.Value // func(w http.ResponseWriter)
	baseURL string       // …/servers/paid
	freeURL string       // …/servers/free (no pricing)
	logPath string

	killed atomic.Int64 // spendKill invocations
}

// newMeterHarness builds a gate with two servers: "paid" (priced, two
// meters: input 3 µ¢/unit + output 15 µ¢/unit) and "free" (no pricing),
// both backed by the same scriptable upstream. Human gates are disabled —
// only spending is under test.
func newMeterHarness(t *testing.T, limits spending.Limits, store *spending.DailyStore) *meterHarness {
	t.Helper()

	h := &meterHarness{calls: &atomic.Int64{}}
	h.respond.Store(func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true,"usage":{"in":10,"out":20}}}`)
	})

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.calls.Add(1)
		h.respond.Load().(func(http.ResponseWriter))(w)
	}))
	t.Cleanup(up.Close)

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New(logPath)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	tracker, err := spending.NewTracker(limits, store)
	if err != nil {
		t.Fatalf("NewTracker: %v", err)
	}

	m := &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "meter-test"},
		MCP: manifest.MCP{Servers: []manifest.MCPServer{
			{
				ID:  "paid",
				URL: up.URL,
				Pricing: &manifest.MCPPricing{Meters: []manifest.PriceMeter{
					{UsagePath: "result.usage.in", USDPerUnit: "0.00000003"},
					{UsagePath: "result.usage.out", USDPerUnit: "0.00000015"},
				}},
			},
			{ID: "free", URL: up.URL},
		}},
	}

	g, err := New(m, nil, nil, logger, tracker)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	g.SetSpendKill(func() { h.killed.Add(1) })

	port, token, err := g.Bind("meterrun1", []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { g.Close() })

	h.gate = g
	h.tracker = tracker
	h.baseURL = fmt.Sprintf("http://127.0.0.1:%d/%s/servers/paid", port, token)
	h.freeURL = fmt.Sprintf("http://127.0.0.1:%d/%s/servers/free", port, token)
	h.logPath = logPath
	return h
}

// waitCharge waits for the async metering (post-response) to reach the
// expected run total.
func (h *meterHarness) waitCharge(t *testing.T, want spending.MicroCents) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.tracker.RunTotal() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("run total = %d µ¢, want %d µ¢", h.tracker.RunTotal(), want)
}

func (h *meterHarness) waitTripped(t *testing.T) spending.Violation {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if v := h.tracker.Tripped(); v != spending.ViolationNone {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("tracker never tripped")
	return spending.ViolationNone
}

func meterEvents(t *testing.T, h *meterHarness) []audit.Entry {
	t.Helper()
	gh := &gateHarness{logPath: h.logPath}
	return auditEvents(t, gh)
}

func TestMeterChargesExactCost(t *testing.T) {
	h := newMeterHarness(t, spending.Limits{PerRun: 1_000_000}, nil)

	code, body := postJSON(t, h.baseURL, toolCallBody("ask"))
	if code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("call failed: %d %s", code, body)
	}

	// 10×3 + 20×15 = 330 µ¢
	h.waitCharge(t, 330)

	// Unpriced server: same upstream, zero charge.
	code, _ = postJSON(t, h.freeURL, toolCallBody("ask"))
	if code != 200 {
		t.Fatalf("free call failed: %d", code)
	}
	time.Sleep(100 * time.Millisecond)
	if h.tracker.RunTotal() != 330 {
		t.Fatalf("unpriced server was charged: %d µ¢", h.tracker.RunTotal())
	}
}

// TestMeterInflatedUsageTripsAndBlocks is the in-process half of the
// adversarial inflation scenario: a server reporting absurd usage trips the
// per-run cap on the FIRST response, the kill fires, and the agent's next
// call — to ANY server, priced or not — is rejected by the tripped gate.
func TestMeterInflatedUsageTripsAndBlocks(t *testing.T) {
	h := newMeterHarness(t, spending.Limits{PerRun: 1_000_000}, nil) // $0.01

	h.respond.Store(func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		// 10^9 output units × 15 µ¢ = 1.5e10 µ¢ = $150 — wildly over cap.
		fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true,"usage":{"in":1,"out":1000000000}}}`)
	})

	if code, _ := postJSON(t, h.baseURL, toolCallBody("ask")); code != 200 {
		t.Fatalf("first call should have been delivered (metering is post-hoc), got %d", code)
	}

	if v := h.waitTripped(t); v != spending.ViolationPerRun {
		t.Fatalf("tripped = %q, want max_per_run_usd", v)
	}
	if h.killed.Load() == 0 {
		t.Fatal("spendKill was not fired")
	}

	upstreamCallsBefore := h.calls.Load()

	// Subsequent calls fail closed at the gate — priced AND unpriced.
	code, body := postJSON(t, h.baseURL, toolCallBody("ask"))
	if code != http.StatusForbidden || !strings.Contains(body, "spending limit") {
		t.Fatalf("tripped gate let a priced call through: %d %s", code, body)
	}
	code, _ = postJSON(t, h.freeURL, toolCallBody("ask"))
	if code != http.StatusForbidden {
		t.Fatalf("tripped gate let an unpriced call through: %d", code)
	}
	if h.calls.Load() != upstreamCallsBefore {
		t.Fatal("a call reached the upstream after the trip")
	}

	// Audit: exactly one limit event.
	var limitEvents int
	for _, e := range meterEvents(t, h) {
		if e.Event == audit.EventSpendingLimit && e.Details["severity"] == "limit" {
			limitEvents++
			if e.Details["limit"] != "max_per_run_usd" {
				t.Errorf("limit event names %v", e.Details["limit"])
			}
		}
	}
	if limitEvents != 1 {
		t.Errorf("want exactly 1 spending limit event, got %d", limitEvents)
	}
}

// TestMeterMissingUsageFailsClosed is the server-wide-pricing granularity
// deliverable: a priced server answering ANY tool without the declared
// usage fields (an "unpriced/free tool", or a server omitting usage to
// zero its bill) is a metering failure that trips and kills the run.
func TestMeterMissingUsageFailsClosed(t *testing.T) {
	h := newMeterHarness(t, spending.Limits{PerRun: 1_000_000}, nil)

	h.respond.Store(func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`) // no usage at all
	})

	postJSON(t, h.baseURL, toolCallBody("supposedly_free_tool"))

	if v := h.waitTripped(t); v != spending.ViolationMetering {
		t.Fatalf("tripped = %q, want metering_failure", v)
	}
	if h.killed.Load() == 0 {
		t.Fatal("spendKill was not fired on metering failure")
	}
	if code, _ := postJSON(t, h.baseURL, toolCallBody("ask")); code != http.StatusForbidden {
		t.Fatal("gate not blocked after metering failure")
	}

	var sawFailure bool
	for _, e := range meterEvents(t, h) {
		if e.Event == audit.EventSpendingLimit && e.Details["severity"] == "metering_failure" {
			sawFailure = true
		}
	}
	if !sawFailure {
		t.Error("no metering_failure audit event")
	}
}

// TestMeterErrorResponseNotCharged: a JSON-RPC error delivered no result,
// so it is not charged and not a metering failure.
func TestMeterErrorResponseNotCharged(t *testing.T) {
	h := newMeterHarness(t, spending.Limits{PerRun: 1000}, nil)

	h.respond.Store(func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"tool exploded"}}`)
	})

	postJSON(t, h.baseURL, toolCallBody("ask"))
	time.Sleep(150 * time.Millisecond)

	if got := h.tracker.RunTotal(); got != 0 {
		t.Fatalf("error response was charged: %d µ¢", got)
	}
	if v := h.tracker.Tripped(); v != spending.ViolationNone {
		t.Fatalf("error response tripped the tracker: %q", v)
	}
}

// TestMeterSSEResponse: usage extraction works when the response arrives
// as a streamable-HTTP SSE stream with notifications around the response.
func TestMeterSSEResponse(t *testing.T) {
	h := newMeterHarness(t, spending.Limits{PerRun: 1_000_000}, nil)

	h.respond.Store(func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n")
		fmt.Fprint(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true,\"usage\":{\"in\":100,\"out\":200}}}\n\n")
	})

	code, _ := postJSON(t, h.baseURL, toolCallBody("ask"))
	if code != 200 {
		t.Fatalf("SSE call failed: %d", code)
	}
	// 100×3 + 200×15 = 3300 µ¢
	h.waitCharge(t, 3300)
}

// TestMeterPrecisionManySmallCharges: 200 sequential priced calls, each
// costing 33 µ¢ ($0.00000033), accumulate to exactly 6600 µ¢ — zero drift
// end to end through the real gate path (json.Number → big.Rat → int64).
func TestMeterPrecisionManySmallCharges(t *testing.T) {
	h := newMeterHarness(t, spending.Limits{PerRun: 1_000_000}, nil)

	h.respond.Store(func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true,"usage":{"in":1,"out":2}}}`)
	})

	const n = 200
	for i := 0; i < n; i++ {
		if code, _ := postJSON(t, h.baseURL, toolCallBody("ask")); code != 200 {
			t.Fatalf("call %d failed: %d", i, code)
		}
	}
	// per call: 1×3 + 2×15 = 33 µ¢
	h.waitCharge(t, n*33)
	if got := spending.MicroCents(n * 33).USD(); got != "0.000066" {
		t.Fatalf("USD rendering = %s", got)
	}
}

// TestMeterDailyCapAcrossStore: with prior spend in the durable store, a
// run whose own total stays under max_per_run still trips max_per_day.
func TestMeterDailyCapAcrossStore(t *testing.T) {
	store := spending.StoreAt(t.TempDir())
	// A "previous run" already spent 9000 µ¢ today.
	if _, err := store.Append("earlier-run", "paid", 9000); err != nil {
		t.Fatal(err)
	}

	h := newMeterHarness(t, spending.Limits{PerRun: 1_000_000, PerDay: 9300}, store)

	// This run's first call charges 330 µ¢ → run total 330 (fine), but day
	// total 9330 > 9300 → per-day trip.
	postJSON(t, h.baseURL, toolCallBody("ask"))

	if v := h.waitTripped(t); v != spending.ViolationPerDay {
		t.Fatalf("tripped = %q, want max_per_day_usd", v)
	}
	if h.killed.Load() == 0 {
		t.Fatal("spendKill was not fired on daily cap")
	}
}

// TestMeterWarnThresholdEvent: crossing warn_at_pct_of_daily writes exactly
// one warning event and does NOT stop the run.
func TestMeterWarnThresholdEvent(t *testing.T) {
	store := spending.StoreAt(t.TempDir())
	h := newMeterHarness(t, spending.Limits{PerDay: 1000, WarnAtPctOfDaily: 30}, store)

	// Each call charges 330 µ¢; the first crosses 30% of 1000 (300 µ¢).
	postJSON(t, h.baseURL, toolCallBody("ask"))
	h.waitCharge(t, 330)
	postJSON(t, h.baseURL, toolCallBody("ask"))
	h.waitCharge(t, 660)

	if v := h.tracker.Tripped(); v != spending.ViolationNone {
		t.Fatalf("warn threshold tripped the tracker: %q", v)
	}

	var warns int
	for _, e := range meterEvents(t, h) {
		if e.Event == audit.EventSpendingLimit && e.Details["severity"] == "warning" {
			warns++
			if e.Details["threshold_pct"] != json.Number("30") && fmt.Sprint(e.Details["threshold_pct"]) != "30" {
				t.Errorf("warning threshold_pct = %v", e.Details["threshold_pct"])
			}
		}
	}
	if warns != 1 {
		t.Errorf("want exactly 1 warning event, got %d", warns)
	}
}
