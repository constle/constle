package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/identity"
	"github.com/constle/constle/internal/spending"
)

// ============================================================
// spending_twoprocess_test.go — the durable-daily-cap deliverables
//
// Everything here execs the REAL constle binary in separate OS processes,
// because "spend survives across independent `constle run` invocations" is
// the property under test:
//
//   - three sequential runs of one DID prove the daily ledger persists
//     across process boundaries: run 1 spends under the cap and finishes;
//     run 2 crosses the cap mid-run and is terminated (its own per-run cap
//     untouched); run 3 is refused before the sandbox even starts. The
//     signed audit log then passes `constle audit verify`.
//   - two SIMULTANEOUS runs of one DID prove the flock actually
//     serializes concurrent charging: with charges interleaved in real
//     time, the shared ledger stops BOTH runs at the shared cap — without
//     the lock each process would have believed itself under the cap.
//   - a manifest with spending limits but no priced MCP servers produces
//     the explicit NOT-enforced warning, never silent nothing.
//
//	sudo -E CONSTLE_E2E=1 go test ./internal/sandbox/ -run Spending -v
// ============================================================

// freshSpendIdentity creates a unique throwaway identity (own DID, own
// ledger directory) and cleans up both after the test — daily ledgers are
// durable by design, so tests must never share a DID across invocations.
func freshSpendIdentity(t *testing.T, tag string) (name, did string) {
	t.Helper()
	name = fmt.Sprintf("spend-e2e-%s-%d", tag, time.Now().UnixNano())
	id, err := identity.Create(name, "")
	if err != nil {
		t.Fatalf("create identity %q: %v", name, err)
	}
	did = id.DID()

	t.Cleanup(func() {
		os.RemoveAll(filepath.Join(identity.Root(), name))
		os.RemoveAll(ledgerDirFor(did))
		os.Remove(audit.DefaultLogPath(name))
	})
	return name, did
}

// ledgerDirFor mirrors the store's per-DID layout (did:key:… → did-key-…).
func ledgerDirFor(did string) string {
	return filepath.Join(spending.Root(), strings.ReplaceAll(did, ":", "-"))
}

// readLedger parses today's ledger for a DID: per-run-id micro-cent totals,
// the ordered run-id sequence, and per-record timestamps.
type ledgerEntry struct {
	TS         time.Time `json:"ts"`
	RunID      string    `json:"run_id"`
	MicroCents int64     `json:"microcents"`
}

func readLedger(t *testing.T, did string) []ledgerEntry {
	t.Helper()
	path := filepath.Join(ledgerDirFor(did), time.Now().UTC().Format("2006-01-02")+".jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ledger %s: %v", path, err)
	}
	var entries []ledgerEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e ledgerEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("corrupt ledger line %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries
}

// spendAgentfile renders a manifest with one priced server (usd_per_unit
// $0.01 on result.usage.units) and the given caps.
func spendAgentfile(t *testing.T, name, did, script string, stubPort int, perRun, perDay string) string {
	t.Helper()
	yaml := fmt.Sprintf(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: %s
  version: "1.0.0"
  did: %s
sandbox:
  image: curlimages/curl:latest
  memory_mb: 128
  command: ["sh","-c",%q]
  network:
    egress: restricted
capabilities: [external_api]
mcp:
  servers:
    - id: paidsrv
      url: "http://127.0.0.1:%d/mcp"
      pricing:
        meters:
          - usage_path: "result.usage.units"
            usd_per_unit: "0.01"
spending:
  max_per_run_usd: %q
  max_per_day_usd: %q
human_gates:
  enabled: false
`, name, did, script, stubPort, perRun, perDay)
	return writeAgentfile(t, name+".yaml", yaml)
}

func runConstle(t *testing.T, bin, backend, agentfile string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := exec.Command(bin, "run", "--backend="+backend, agentfile)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// TestSpendingDailyPersistsAcrossProcesses is the durable-tracking
// deliverable, in three independent constle run processes on one DID.
func TestSpendingDailyPersistsAcrossProcesses(t *testing.T) {
	requireE2E(t)
	bin := buildConstle(t)

	for name := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			agentName, did := freshSpendIdentity(t, name)
			// 30 units × $0.01 = $0.30 per call. Day cap $1.00; per-run cap
			// $10 — far away, so only the daily cap can terminate anything.
			stub := startPricedStub(t, 30)

			callScript := func(calls int, probeSurvival bool) string {
				s := mcpCallHelper
				for i := 1; i <= calls; i++ {
					s += fmt.Sprintf(`
R=$(call "$CONSTLE_MCP_PAIDSRV_URL" paid_tool)
echo "$R" | grep -q '"result"' && echo "CALL%d: OK" || echo "CALL%d: FAILED"
sleep 1
`, i, i)
				}
				if probeSurvival {
					s += "\nsleep 45\necho RUN_SURVIVED_SPENDING_KILL\n"
				} else {
					s += "\necho SCRIPT_DONE\n"
				}
				return s
			}

			// ---- Run 1: $0.60 of a $1.00 day — must complete normally.
			out1, err1 := runConstle(t, bin, name,
				spendAgentfile(t, agentName, did, callScript(2, false), stub.port(), "10.00", "1.00"))
			if err1 != nil {
				t.Fatalf("[%s] run 1 should have succeeded: %v\n%s", name, err1, out1)
			}
			for _, want := range []string{"CALL1: OK", "CALL2: OK", "SCRIPT_DONE"} {
				if !strings.Contains(out1, want) {
					t.Fatalf("[%s] run 1 missing %q:\n%s", name, want, out1)
				}
			}

			entries := readLedger(t, did)
			var total int64
			for _, e := range entries {
				total += e.MicroCents
			}
			if total != 60_000_000 { // $0.60 exactly
				t.Fatalf("[%s] after run 1 ledger total = %d µ¢, want exactly 60000000", name, total)
			}

			// ---- Run 2: a SEPARATE process. Its 2nd call pushes the day to
			// $1.20 > $1.00 → terminated mid-run, though this run alone
			// ($0.60) is far under its own $10 per-run cap.
			stubCallsBefore := len(stub.calledTools())
			out2, err2 := runConstle(t, bin, name,
				spendAgentfile(t, agentName, did, callScript(3, true), stub.port(), "10.00", "1.00"))
			if err2 == nil {
				t.Fatalf("[%s] run 2 should have been terminated by the daily cap:\n%s", name, out2)
			}
			// The agent's own stdout after the kill is unreliable (the kill
			// can outrun the guest's flush), so the proof is host-side: the
			// CLI's attribution line, the stub's ground-truth call count,
			// and the durable ledger arithmetic.
			if strings.Contains(out2, "CALL3: OK") || strings.Contains(out2, "RUN_SURVIVED_SPENDING_KILL") {
				t.Errorf("[%s] run 2 completed a call after the daily cap was crossed:\n%s", name, out2)
			}
			if !strings.Contains(out2, "spending limit (max_per_day_usd)") {
				t.Errorf("[%s] run 2 was not attributed to the daily spending limit:\n%s", name, out2)
			}
			if got := len(stub.calledTools()) - stubCallsBefore; got != 2 {
				t.Errorf("[%s] run 2: real server saw %d calls, want exactly 2 — "+
					"the 2nd crossed the cap, the 3rd must never arrive", name, got)
			}
			entries = readLedger(t, did)
			total = 0
			for _, e := range entries {
				total += e.MicroCents
			}
			if total != 120_000_000 || len(entries) != 4 {
				t.Errorf("[%s] after run 2 ledger = %d records / %d µ¢, want 4 records / 120000000 exactly",
					name, len(entries), total)
			}

			// ---- Run 3: refused BEFORE the sandbox starts — the durable
			// ledger already exceeds the cap.
			stubCallsBefore = len(stub.calledTools())
			out3, err3 := runConstle(t, bin, name,
				spendAgentfile(t, agentName, did, callScript(1, false), stub.port(), "10.00", "1.00"))
			if err3 == nil {
				t.Fatalf("[%s] run 3 should have been refused at start:\n%s", name, out3)
			}
			if !strings.Contains(out3, "refusing to start") {
				t.Errorf("[%s] run 3 was not refused with the fail-closed message:\n%s", name, out3)
			}
			if strings.Contains(out3, "sandbox started") {
				t.Errorf("[%s] run 3 started a sandbox despite an exhausted budget:\n%s", name, out3)
			}
			if got := len(stub.calledTools()) - stubCallsBefore; got != 0 {
				t.Errorf("[%s] run 3 reached the real server %d times, want 0", name, got)
			}

			// ---- The signed audit log carries the whole story and verifies:
			// spending events are Ed25519-signed and hash-chained like every
			// other event.
			logPath := audit.DefaultLogPath(agentName)
			verifyOut, verifyErr := exec.Command(bin, "audit", "verify", "--did="+did, logPath).CombinedOutput()
			if verifyErr != nil {
				t.Errorf("[%s] audit verify failed: %v\n%s", name, verifyErr, verifyOut)
			}
			logData, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("read audit log: %v", err)
			}
			for _, want := range []string{
				string(audit.EventTerminatedByLimit),
				string(audit.EventSpendingLimit),
				"max_per_day_usd",
				"run_refused",
			} {
				if !strings.Contains(string(logData), want) {
					t.Errorf("[%s] audit log missing %q", name, want)
				}
			}
		})
	}
}

// TestSpendingConcurrentRunsShareTheCap is the TRUE-concurrency deliverable:
// two constle run processes for the SAME DID charging at the same moment.
// Each alone would spend $2.00 — far over the shared $1.00 daily cap but
// under its own $10 per-run cap, so ONLY the flock-serialized shared ledger
// can stop them. Proof of serialization: the ledger's records interleave in
// time across both run ids, every record survived (total = count × charge,
// exactly), and charging stopped within two in-flight charges of the cap.
func TestSpendingConcurrentRunsShareTheCap(t *testing.T) {
	requireE2E(t)
	bin := buildConstle(t)

	for name := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			agentName, did := freshSpendIdentity(t, "conc-"+name)
			// 2 units × $0.01 = $0.02 per call; 100 calls = $2.00 per process.
			stub := startPricedStub(t, 2)

			script := mcpCallHelper + `
i=0
while [ $i -lt 100 ]; do
  R=$(call "$CONSTLE_MCP_PAIDSRV_URL" paid_tool)
  echo "$R" | grep -q '"result"' || { echo "BLOCKED_AT_CALL_$i"; exit 7; }
  i=$((i+1))
  sleep 0.5
done
echo LOOP_DONE
`
			agentfile := spendAgentfile(t, agentName, did, script, stub.port(), "10.00", "1.00")

			type result struct {
				out string
				err error
			}
			results := make(chan result, 2)
			for p := 0; p < 2; p++ {
				go func() {
					out, err := runConstle(t, bin, name, agentfile)
					results <- result{out, err}
				}()
			}

			var outs []string
			for p := 0; p < 2; p++ {
				select {
				case r := <-results:
					outs = append(outs, r.out)
					if r.err == nil {
						t.Errorf("[%s] a process completed all 100 calls ($2.00) under a shared $1.00 cap:\n%s", name, r.out)
					}
				case <-time.After(5 * time.Minute):
					t.Fatalf("[%s] concurrent runs did not finish within 5 minutes", name)
				}
			}
			for _, out := range outs {
				if strings.Contains(out, "LOOP_DONE") {
					t.Errorf("[%s] a process finished its full loop — the shared cap did not stop it:\n%s", name, out)
				}
			}

			entries := readLedger(t, did)

			// Exact arithmetic: every record is one $0.02 charge; the flock
			// lost nothing and invented nothing.
			var total int64
			perRun := map[string]int{}
			firstTS := map[string]time.Time{}
			lastTS := map[string]time.Time{}
			var order []string
			for _, e := range entries {
				total += e.MicroCents
				if e.MicroCents != 2_000_000 {
					t.Fatalf("[%s] ledger record of %d µ¢, want every record = 2000000", name, e.MicroCents)
				}
				if len(order) == 0 || order[len(order)-1] != e.RunID {
					order = append(order, e.RunID)
				}
				perRun[e.RunID]++
				if _, ok := firstTS[e.RunID]; !ok {
					firstTS[e.RunID] = e.TS
				}
				lastTS[e.RunID] = e.TS
			}

			if got, want := total, int64(len(entries))*2_000_000; got != want {
				t.Errorf("[%s] ledger total %d ≠ %d records × 2000000 — drift or lost update", name, got, want)
			}
			if len(perRun) != 2 {
				t.Fatalf("[%s] ledger has %d run ids, want 2 (both processes must have charged): %v", name, len(perRun), perRun)
			}

			// The cap actually held: crossed (both were terminated) but never
			// by more than the two possible in-flight charges.
			const dayCap = 100_000_000 // $1.00
			if total <= dayCap {
				t.Errorf("[%s] total %d µ¢ never crossed the cap, yet both runs were terminated?", name, total)
			}
			if total > dayCap+2*2_000_000 {
				t.Errorf("[%s] total %d µ¢ overshot the cap by more than two in-flight charges — enforcement lagged the ledger", name, total)
			}

			// TRUE concurrency, not luck: the two processes' charge windows
			// overlapped in time AND their records interleave in the ledger.
			var ids []string
			for id := range perRun {
				ids = append(ids, id)
			}
			a, b := ids[0], ids[1]
			overlapStart := firstTS[a]
			if firstTS[b].After(overlapStart) {
				overlapStart = firstTS[b]
			}
			overlapEnd := lastTS[a]
			if lastTS[b].Before(overlapEnd) {
				overlapEnd = lastTS[b]
			}
			if !overlapStart.Before(overlapEnd) {
				t.Errorf("[%s] charge windows did not overlap (a: %v–%v, b: %v–%v) — the runs never charged concurrently",
					name, firstTS[a], lastTS[a], firstTS[b], lastTS[b])
			}
			if len(order) < 3 {
				t.Errorf("[%s] ledger order %v has no interleaving — the runs never raced on the lock", name, order)
			}

			t.Logf("[%s] shared-cap outcome: %d charges, total $%s, interleavings=%d, per-run=%v",
				name, len(entries), spending.MicroCents(total).USD(), len(order)-1, perRun)
		})
	}
}

// TestSpendingUnenforcedWarningE2E: the real binary, a manifest with
// spending limits but NO priced MCP servers — the run must print the
// explicit NOT-enforced warning and still work, rather than silently
// pretending the limits mean something.
func TestSpendingUnenforcedWarningE2E(t *testing.T) {
	requireE2E(t)
	bin := buildConstle(t)

	for name := range conformanceBackends(t) {
		t.Run(name, func(t *testing.T) {
			yaml := `apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: spend-warn-e2e
  version: "1.0.0"
sandbox:
  image: curlimages/curl:latest
  memory_mb: 128
  command: ["sh","-c","echo agent ran fine"]
  network:
    egress: restricted
    allowed_hosts: ["api.example.com"]
capabilities: [external_api]
spending:
  max_per_run_usd: "0.50"
`
			out, err := runConstle(t, bin, name, writeAgentfile(t, "warn.yaml", yaml))
			if err != nil {
				t.Fatalf("[%s] run failed: %v\n%s", name, err, out)
			}
			if !strings.Contains(out, "NOT enforced") {
				t.Errorf("[%s] no explicit NOT-enforced warning for unmeterable spending limits:\n%s", name, out)
			}
			if !strings.Contains(out, "agent ran fine") {
				t.Errorf("[%s] agent did not run:\n%s", name, out)
			}
		})
	}
}
