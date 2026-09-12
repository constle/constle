package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================
// firecracker_state.go — run tracking without trusting metadata
//
// Docker uses container labels as the source of truth for `constle ps`.
// Firecracker has no such registry, so each run writes a state file to
// /var/lib/constle/runs/<id>/state.json — but the file alone is NEVER
// treated as proof that a run is alive. A run counts as running only if
// /proc/<pid>/cmdline still names a firecracker process carrying this
// run's ID (jailer passes `--id <runid>` through to firecracker), which
// makes the check safe against PID reuse after a crash.
//
// A run's identity is its directory name under /var/lib/constle/runs, and
// every entry point checks that name against the shape newRunID mints
// before building a path from it. The file's own run_id field is
// informational: no path, device or table name is ever derived from it,
// because what gets removed as root is exactly what a substituted file
// would redirect.
// ============================================================

// fcRunState is the persisted record of one Firecracker-backed run.
// Written 0644 inside a 0755 directory so `constle ps` works without root.
type fcRunState struct {
	RunID          string    `json:"run_id"`
	AgentName      string    `json:"agent_name"`
	VMPid          int       `json:"vm_pid"`
	SquidPID       int       `json:"squid_pid"`
	TAPDevice      string    `json:"tap_device"` // for inspection only: teardown derives the device from the run ID
	GatewayIP      string    `json:"gateway_ip"`
	StartedAt      time.Time `json:"started_at"`
	IsolationLevel string    `json:"isolation_level,omitempty"`
}

// FCRunInfo is the public view of a Firecracker run for `constle ps`.
type FCRunInfo struct {
	RunID     string
	AgentName string
	Running   bool
	StartedAt time.Time
}

func fcStatePath(runID string) string {
	return filepath.Join(fcRunsDir, runID, "state.json")
}

func writeFCState(st *fcRunState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(fcStatePath(st.RunID), data, 0644)
}

func readFCState(runID string) (*fcRunState, error) {
	data, err := os.ReadFile(fcStatePath(runID))
	if err != nil {
		return nil, err
	}
	var st fcRunState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("corrupt state file for run %s: %w", runID, err)
	}
	return &st, nil
}

// FirecrackerRunExists reports whether a state file exists for runID —
// used by `constle stop` to route between backends. An ID that is not
// shaped like a run ID is never joined onto the runs directory: filepath
// cleaning would let "../" segments name a file anywhere on the host.
func FirecrackerRunExists(runID string) bool {
	if ValidateRunID(runID) != nil {
		return false
	}
	_, err := os.Stat(fcStatePath(runID))
	return err == nil
}

// fcProcessAlive reports whether pid is a live firecracker process that
// belongs to runID, verified against /proc/<pid>/cmdline.
func fcProcessAlive(pid int, runID string) bool {
	return cmdlineMatches(pid, "firecracker", runID)
}

// cmdlineMatches reads /proc/<pid>/cmdline (NUL-separated argv) and reports
// whether argv[0] contains binaryName and any argument equals wantArg.
// wantArg == "" only checks the binary name.
func cmdlineMatches(pid int, binaryName, wantArg string) bool {
	if pid <= 0 {
		return false
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	argv := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	if len(argv) == 0 || !strings.Contains(filepath.Base(argv[0]), binaryName) {
		return false
	}
	if wantArg == "" {
		return true
	}
	for _, arg := range argv[1:] {
		if arg == wantArg {
			return true
		}
	}
	return false
}

// ListFirecrackerRuns returns every recorded run with its live-verified
// status. Corrupt or unreadable entries are skipped — ps is best-effort.
func ListFirecrackerRuns() []FCRunInfo {
	entries, err := os.ReadDir(fcRunsDir)
	if err != nil {
		return nil
	}

	var runs []FCRunInfo
	for _, entry := range entries {
		// The directory name is the run's identity; an entry not named
		// like a run ID was not created by constle and is not one.
		runID := entry.Name()
		if !entry.IsDir() || ValidateRunID(runID) != nil {
			continue
		}
		st, err := readFCState(runID)
		if err != nil {
			continue
		}
		runs = append(runs, FCRunInfo{
			RunID:     runID,
			AgentName: st.AgentName,
			Running:   fcProcessAlive(st.VMPid, runID),
			StartedAt: st.StartedAt,
		})
	}
	return runs
}

// StopFirecrackerRun force-stops a run by ID and removes all its host
// resources. Used by `constle stop`; requires root for the teardown.
//
// runID arrives from the command line, so it is checked before anything
// else — ahead of the root check, so a malformed ID is reported as such,
// and ahead of any path built from it.
func StopFirecrackerRun(runID string) error {
	if err := ValidateRunID(runID); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("stopping a firecracker run requires root — re-run with sudo")
	}
	st, err := readFCState(runID)
	if err != nil {
		return fmt.Errorf("no state for run %s: %w", runID, err)
	}

	// Give the guest a brief chance to shut down cleanly before the kill.
	if fcProcessAlive(st.VMPid, runID) {
		if sendCtrlAltDel(runID) == nil {
			for i := 0; i < 30 && fcProcessAlive(st.VMPid, runID); i++ {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	if errs := teardownFirecrackerRun(runID, st); len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// teardownFirecrackerRun removes every host resource of a run: VMM process,
// squid process, TAP device, nftables table, chroot, and the run directory.
// Best-effort and idempotent; returns a list of error strings like the
// Docker backend's Stop.
//
// runID is the directory the state was read from. It is re-checked here
// regardless of what the caller did: this is the function that removes as
// root, and Stop and the abandoned-run sweep reach it without going
// through StopFirecrackerRun. Every path, device and table name removed
// here is derived from it, never from the state file. The file sits 0644 in a root-owned
// directory, but what this function removes as root is exactly what a
// substituted file would redirect, so its run_id and tap_device fields
// carry no authority. Only the PIDs are taken from it, and each is checked
// against /proc before it is signalled.
func teardownFirecrackerRun(runID string, st *fcRunState) []string {
	if err := ValidateRunID(runID); err != nil {
		return []string{err.Error()}
	}
	var errs []string

	if fcProcessAlive(st.VMPid, runID) {
		if err := killPID(st.VMPid); err != nil {
			errs = append(errs, fmt.Sprintf("kill vm %d: %v", st.VMPid, err))
		}
	}

	// Only signal the squid PID if it still looks like our squid — the PID
	// may have been reused after a host crash. SIGTERM first so Squid can
	// flush its access log, but never report success while it is still
	// alive (its shutdown takes ~2s even with shutdown_lifetime 0):
	// wait for it to exit, escalate to SIGKILL, and surface survival.
	//
	// The signal errors themselves are discarded on purpose: what matters
	// is not whether the signal was accepted but whether the process is
	// gone, and waitProcessGone answers that directly — a signal that
	// silently failed still ends up reported below as "still running".
	if cmdlineMatches(st.SquidPID, "squid", "") {
		_ = termProcess(st.SquidPID)
		if !waitProcessGone(st.SquidPID, "squid", 5*time.Second) {
			_ = killProcess(st.SquidPID)
			if !waitProcessGone(st.SquidPID, "squid", 2*time.Second) {
				errs = append(errs, fmt.Sprintf("squid %d still running after SIGKILL", st.SquidPID))
			}
		}
	}

	if err := deleteTAP(fcTAPName(runID)); err != nil {
		errs = append(errs, err.Error())
	}
	if err := deleteNFTRules(runID); err != nil {
		errs = append(errs, err.Error())
	}

	if err := os.RemoveAll(filepath.Join(fcJailDir, "firecracker", runID)); err != nil {
		errs = append(errs, fmt.Sprintf("rm chroot: %v", err))
	}
	if err := os.RemoveAll(filepath.Join(fcRunsDir, runID)); err != nil {
		errs = append(errs, fmt.Sprintf("rm run dir: %v", err))
	}
	return errs
}

// waitProcessGone polls until pid no longer looks like binaryName or the
// timeout elapses. A reaped, exited, or reused PID all count as gone.
func waitProcessGone(pid int, binaryName string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !cmdlineMatches(pid, binaryName, "") {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !cmdlineMatches(pid, binaryName, "")
}

// cleanupAbandonedFirecracker removes resources of runs whose VMM is no
// longer alive — the Firecracker analog of the Docker backend's
// cleanupAbandoned. Silent on all errors: housekeeping, not a critical path.
func cleanupAbandonedFirecracker() {
	entries, err := os.ReadDir(fcRunsDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		// Only entries named like a run ID are constle's to remove; anything
		// else under the runs directory is left exactly as found.
		runID := entry.Name()
		if !entry.IsDir() || ValidateRunID(runID) != nil {
			continue
		}
		st, err := readFCState(runID)
		if err != nil {
			// State never written or corrupt — remove the debris but keep
			// directories that are too young to judge (Start may be racing).
			if info, statErr := entry.Info(); statErr == nil && time.Since(info.ModTime()) > time.Minute {
				_ = os.RemoveAll(filepath.Join(fcRunsDir, runID))
			}
			continue
		}
		if fcProcessAlive(st.VMPid, runID) {
			continue
		}
		teardownFirecrackerRun(runID, st)
	}
}
