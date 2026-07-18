package sandbox

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// TestTeardownKillsHostSquid verifies that teardownFirecrackerRun terminates
// the per-run host Squid — the exact resource observed leaking when a run is
// stopped after a supervisor crash (kill -9 on constle run, then constle stop).
//
// Requires root and a squid binary; skipped otherwise. Uses the real
// startHostSquid so the spawned process matches production exactly.
func TestTeardownKillsHostSquid(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (squid drops to the proxy user)")
	}
	if _, err := exec.LookPath("squid"); err != nil {
		t.Skip("squid not installed")
	}

	// The run dir must be traversable by squid's effective user, like the
	// production /var/lib/constle/runs/<id> (0755).
	runDir, err := os.MkdirTemp("/tmp", "constle-squid-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runDir)
	if err := os.Chmod(runDir, 0755); err != nil {
		t.Fatal(err)
	}

	pid, _, err := startHostSquid("sqtest01", runDir, "127.0.0.1", nil, nil)
	if err != nil {
		t.Fatalf("startHostSquid: %v", err)
	}
	defer syscall.Kill(pid, syscall.SIGKILL) // last-resort cleanup on failure

	if !cmdlineMatches(pid, "squid", "") {
		t.Fatalf("freshly started squid (pid %d) not recognized by cmdlineMatches", pid)
	}

	errs := teardownFirecrackerRun(&fcRunState{
		RunID:    "sqtest01",
		SquidPID: pid,
	})
	// nft cleanup errors are expected here (no table was installed); only
	// squid survival matters for this test.
	t.Logf("teardown errs (informational): %v", errs)

	// The contract: when teardown returns, the proxy is gone. Reporting
	// success while squid is still shutting down is exactly the bug where
	// `constle stop` printed ✓ and ps still showed the per-run squid.
	if cmdlineMatches(pid, "squid", "") {
		t.Fatalf("squid (pid %d) still running when teardownFirecrackerRun returned", pid)
	}
}
