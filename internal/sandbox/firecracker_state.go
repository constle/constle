package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
// ============================================================

// fcRunState is the persisted record of one Firecracker-backed run.
// Written 0644 inside a 0755 directory so `constle ps` works without root.
type fcRunState struct {
	RunID          string    `json:"run_id"`
	AgentName      string    `json:"agent_name"`
	VMPid          int       `json:"vm_pid"`
	SquidPID       int       `json:"squid_pid"`
	TAPDevice      string    `json:"tap_device"`
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
// used by `constle stop` to route between backends.
func FirecrackerRunExists(runID string) bool {
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
		if !entry.IsDir() {
			continue
		}
		st, err := readFCState(entry.Name())
		if err != nil {
			continue
		}
		runs = append(runs, FCRunInfo{
			RunID:     st.RunID,
			AgentName: st.AgentName,
			Running:   fcProcessAlive(st.VMPid, st.RunID),
			StartedAt: st.StartedAt,
		})
	}
	return runs
}

// StopFirecrackerRun force-stops a run by ID and removes all its host
// resources. Used by `constle stop`; requires root for the teardown.
func StopFirecrackerRun(runID string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("stopping a firecracker run requires root — re-run with sudo")
	}
	st, err := readFCState(runID)
	if err != nil {
		return fmt.Errorf("no state for run %s: %w", runID, err)
	}

	// Give the guest a brief chance to shut down cleanly before the kill.
	if fcProcessAlive(st.VMPid, st.RunID) {
		if sendCtrlAltDel(runID) == nil {
			for i := 0; i < 30 && fcProcessAlive(st.VMPid, st.RunID); i++ {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	if errs := teardownFirecrackerRun(st); len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// teardownFirecrackerRun removes every host resource of a run: VMM process,
// squid process, TAP device, nftables table, chroot, and the run directory.
// Best-effort and idempotent; returns a list of error strings like the
// Docker backend's Stop.
func teardownFirecrackerRun(st *fcRunState) []string {
	var errs []string

	if fcProcessAlive(st.VMPid, st.RunID) {
		if err := killPID(st.VMPid); err != nil {
			errs = append(errs, fmt.Sprintf("kill vm %d: %v", st.VMPid, err))
		}
	}

	// Only signal the squid PID if it still looks like our squid — the PID
	// may have been reused after a host crash.
	if cmdlineMatches(st.SquidPID, "squid", "") {
		if proc, err := os.FindProcess(st.SquidPID); err == nil {
			proc.Signal(syscall.SIGTERM)
		}
	}

	if st.TAPDevice != "" {
		if err := deleteTAP(st.TAPDevice); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if err := deleteNFTRules(st.RunID); err != nil {
		errs = append(errs, err.Error())
	}

	if err := os.RemoveAll(filepath.Join(fcJailDir, "firecracker", st.RunID)); err != nil {
		errs = append(errs, fmt.Sprintf("rm chroot: %v", err))
	}
	if err := os.RemoveAll(filepath.Join(fcRunsDir, st.RunID)); err != nil {
		errs = append(errs, fmt.Sprintf("rm run dir: %v", err))
	}
	return errs
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
		if !entry.IsDir() {
			continue
		}
		st, err := readFCState(entry.Name())
		if err != nil {
			// State never written or corrupt — remove the debris but keep
			// directories that are too young to judge (Start may be racing).
			if info, statErr := entry.Info(); statErr == nil && time.Since(info.ModTime()) > time.Minute {
				os.RemoveAll(filepath.Join(fcRunsDir, entry.Name()))
			}
			continue
		}
		if fcProcessAlive(st.VMPid, st.RunID) {
			continue
		}
		teardownFirecrackerRun(st)
	}
}
