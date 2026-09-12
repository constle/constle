package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// useTempStateDirs points the per-run state directory and the jailer chroot
// base at a scratch tree for the duration of the test, so nothing below
// reads or removes anything under /var/lib/constle. It swaps package-level
// variables, so no test that calls it — or that reads fcRunsDir/fcJailDir
// while it is in effect — may use t.Parallel.
func useTempStateDirs(t *testing.T) (runsDir, jailDir string) {
	t.Helper()
	root := t.TempDir()
	runsDir = filepath.Join(root, "runs")
	jailDir = filepath.Join(root, "jail")
	mkdirAll(t, runsDir, jailDir)
	origRuns, origJail := fcRunsDir, fcJailDir
	fcRunsDir, fcJailDir = runsDir, jailDir
	t.Cleanup(func() { fcRunsDir, fcJailDir = origRuns, origJail })
	return runsDir, jailDir
}

// shimNetTools puts stub `ip` and `nft` executables first on PATH that only
// record their arguments, and returns a function that reads the recorded
// calls. teardown execs both binaries; with the stubs the test is hermetic
// (no root, no real device or table is touched) and the arguments become
// assertable.
func shimNetTools(t *testing.T) (calls func() string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub executables need a POSIX shell")
	}
	bin := t.TempDir()
	logPath := filepath.Join(bin, "calls.log")
	for _, name := range []string{"ip", "nft"} {
		script := "#!/bin/sh\necho \"" + name + " $*\" >> \"" + logPath + "\"\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() string {
		out, err := os.ReadFile(logPath)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return string(out)
	}
}

// startFakeFirecracker starts a process that fcProcessAlive recognises as
// the VMM of runID — argv[0] ends in "firecracker" and an argument equals
// the run ID, as jailer's `--id` does — and returns its PID. It is killed
// and reaped when the test ends if teardown has not killed it first.
func startFakeFirecracker(t *testing.T, runID string) int {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc/<pid>/cmdline")
	}
	exe := filepath.Join(t.TempDir(), "firecracker")
	if err := os.Symlink("/bin/sh", exe); err != nil {
		t.Fatal(err)
	}
	// A loop, not a single command, so the shell cannot exec-replace itself
	// with `sleep` and lose the argv this test relies on.
	cmd := exec.Command(exe, "-c", "while :; do sleep 1; done", "firecracker", "--id", runID)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	// Start returns once the child's close-on-exec pipe shuts, which the
	// kernel does a moment before it records the new image's argv, so
	// /proc/<pid>/cmdline can still read empty here: wait to be recognised.
	deadline := time.Now().Add(2 * time.Second)
	for !fcProcessAlive(cmd.Process.Pid, runID) {
		if time.Now().After(deadline) {
			t.Fatalf("fake firecracker (pid %d) not recognised by fcProcessAlive", cmd.Process.Pid)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cmd.Process.Pid
}

func mkdirAll(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
}

func writeState(t *testing.T, dir, body string) {
	t.Helper()
	mkdirAll(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

// backdate sets a directory's mtime two minutes into the past, so the
// abandoned-run sweep no longer suspects a racing Start, and checks that
// the filesystem actually honours it — one that does not would otherwise
// surface as a sweep bug.
func backdate(t *testing.T, dirs ...string) {
	t.Helper()
	old := time.Now().Add(-2 * time.Minute)
	for _, d := range dirs {
		if err := os.Chtimes(d, old, old); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if info.ModTime().After(old.Add(time.Second)) {
			t.Skipf("filesystem does not honour directory mtimes (%s reads %v after Chtimes to %v)", d, info.ModTime(), old)
		}
	}
}

// The validation must not get in the way of the happy path: a run stored
// under its own 16-hex directory is still found.
func TestFirecrackerRunExistsFindsValidRun(t *testing.T) {
	runsDir, _ := useTempStateDirs(t)
	const runID = "76935e132f9be8e9"

	if FirecrackerRunExists(runID) {
		t.Fatalf("FirecrackerRunExists(%q) = true before any state was written", runID)
	}
	writeState(t, filepath.Join(runsDir, runID), `{"run_id": "76935e132f9be8e9"}`)
	if !FirecrackerRunExists(runID) {
		t.Errorf("FirecrackerRunExists(%q) = false with its state file in place", runID)
	}
}

// A run ID reaches `constle stop` straight from the command line and is
// joined onto the runs directory to find the state file. filepath.Join
// cleans "../" segments, so before validation an ID like "../evil" made
// FirecrackerRunExists find — and StopFirecrackerRun load, as root — a state
// file the caller had planted anywhere on the host, whose fields then drove
// the teardown. Both entry points must reject the ID before building a path
// from it, even though the file it points at exists.
func TestStopRejectsTraversalRunID(t *testing.T) {
	runsDir, _ := useTempStateDirs(t)

	// Plant a state file beside the runs directory, reachable only through
	// a ".." segment. Its content is deliberately not JSON: if either entry
	// point read it before rejecting the ID, the error would be the parse
	// failure — or, without root, the root check — not the validation error
	// asserted exactly below.
	evilDir := filepath.Join(filepath.Dir(runsDir), "evil")
	writeState(t, evilDir, `not json`)

	const traversal = "../evil"

	// The planted file must be exactly where an unchecked ID would look, or
	// the test proves nothing about the vector.
	if _, err := os.Stat(fcStatePath(traversal)); err != nil {
		t.Fatalf("test setup: %q does not reach the planted state file: %v", fcStatePath(traversal), err)
	}

	if FirecrackerRunExists(traversal) {
		t.Errorf("FirecrackerRunExists(%q) = true; a traversal ID must never resolve to a state file", traversal)
	}

	want := ValidateRunID(traversal)
	if want == nil {
		t.Fatalf("test bug: %q passes ValidateRunID", traversal)
	}
	err := StopFirecrackerRun(traversal)
	if err == nil || err.Error() != want.Error() {
		t.Errorf("StopFirecrackerRun(%q) error = %v, want exactly %q (the ID rejected before anything is read)", traversal, err, want)
	}
}

// The state file sits in a root-owned directory, but the resources teardown
// removes as root are precisely what a substituted file would redirect — so
// nothing torn down may be named by the file. Given a state whose run_id
// and tap_device point elsewhere, teardown must remove the directories,
// the TAP device and the nftables table derived from the validated ID and
// leave the file's targets alone.
func TestTeardownDerivesPathsFromValidatedRunID(t *testing.T) {
	runsDir, jailDir := useTempStateDirs(t)
	calls := shimNetTools(t)
	const runID = "76935e132f9be8e9"

	runDir := filepath.Join(runsDir, runID)
	chrootDir := filepath.Join(jailDir, "firecracker", runID)
	// One traversal reaches a planted directory from both places the file's
	// run_id used to be joined: <root>/victim from <jail>/firecracker/<id>
	// and <root>/../victim from <runs>/<id>.
	victims := []string{
		filepath.Join(filepath.Dir(runsDir), "victim"),
		filepath.Join(filepath.Dir(runsDir), "..", "victim"),
	}
	mkdirAll(t, runDir, filepath.Join(chrootDir, "root"))
	mkdirAll(t, victims...)

	st := &fcRunState{
		RunID:     "../../victim",
		TAPDevice: "ctnosuchdevice",
	}
	if errs := teardownFirecrackerRun(runID, st); len(errs) > 0 {
		t.Errorf("teardownFirecrackerRun(%q) errs = %q, want none with stubbed ip/nft", runID, errs)
	}

	for _, d := range []string{runDir, chrootDir} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("%s still exists after teardown (err=%v)", d, err)
		}
	}
	for _, v := range victims {
		if _, err := os.Stat(v); err != nil {
			t.Errorf("teardown followed the state file's run_id and removed %s: %v", v, err)
		}
	}

	log := calls()
	for _, want := range []string{
		"ip link del " + fcTAPName(runID) + "\n",
		"nft delete table inet " + nftTableName(runID) + "\n",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("teardown did not run %q; calls:\n%s", strings.TrimSpace(want), log)
		}
	}
	for _, fromFile := range []string{st.TAPDevice, st.RunID} {
		if strings.Contains(log, fromFile) {
			t.Errorf("teardown handed the state file's %q to ip/nft; calls:\n%s", fromFile, log)
		}
	}
}

// teardown is the function that removes directories as root, so it is also
// the last place an ID that is not a run ID may pass through — and nothing
// at all may happen on the way out.
func TestTeardownRefusesMalformedRunID(t *testing.T) {
	runsDir, _ := useTempStateDirs(t)
	calls := shimNetTools(t)
	victim := filepath.Join(filepath.Dir(runsDir), "victim")
	mkdirAll(t, victim)

	errs := teardownFirecrackerRun("../victim", &fcRunState{RunID: "../victim"})
	if len(errs) != 1 || !strings.Contains(errs[0], "invalid run ID") {
		t.Errorf("teardownFirecrackerRun(%q) errs = %q, want exactly the invalid-run-ID error", "../victim", errs)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("teardown acted on a malformed run ID and removed %s: %v", victim, err)
	}
	if log := calls(); log != "" {
		t.Errorf("teardown ran ip/nft for a malformed run ID; calls:\n%s", log)
	}
}

// The PIDs are the only fields teardown still takes from the state file, and
// each is checked against /proc under the validated ID — a file that names
// another run's ID and that run's live VMM must not get it killed.
func TestTeardownPIDGuardUsesValidatedRunID(t *testing.T) {
	useTempStateDirs(t)
	shimNetTools(t)
	const runID, otherID = "76935e132f9be8e9", "aaaaaaaaaaaaaaaa"

	otherPid := startFakeFirecracker(t, otherID)
	_ = teardownFirecrackerRun(runID, &fcRunState{RunID: otherID, VMPid: otherPid})
	if !fcProcessAlive(otherPid, otherID) {
		t.Fatalf("tearing down run %s killed the VMM of run %s (pid %d) named by the state file", runID, otherID, otherPid)
	}

	// The run's own VMM, carrying its own ID, is killed.
	ownPid := startFakeFirecracker(t, runID)
	_ = teardownFirecrackerRun(runID, &fcRunState{RunID: runID, VMPid: ownPid})
	if !waitProcessGone(ownPid, "firecracker", 2*time.Second) {
		t.Errorf("teardown left the run's own VMM (pid %d) alive", ownPid)
	}
}

// `constle ps` and the abandoned-run sweep walk the runs directory. The
// directory name is the run's identity: an inconsistent run_id in the file
// must not be reported (or acted on), and entries not named like a run ID
// are not constle's and are ignored.
func TestListFirecrackerRunsUsesDirectoryName(t *testing.T) {
	runsDir, _ := useTempStateDirs(t)
	const runID = "76935e132f9be8e9"

	writeState(t, filepath.Join(runsDir, runID),
		fmt.Sprintf(`{"run_id": "../../etc", "agent_name": "agent-%s", "vm_pid": 0}`, runID))
	writeState(t, filepath.Join(runsDir, "not-a-run"),
		`{"run_id": "not-a-run", "agent_name": "foreign", "vm_pid": 0}`)
	writeState(t, filepath.Join(runsDir, "..hidden"),
		fmt.Sprintf(`{"run_id": %q, "agent_name": "foreign", "vm_pid": 0}`, runID))
	mkdirAll(t, filepath.Join(runsDir, "0123456789abcdef")) // never wrote its state

	runs := ListFirecrackerRuns()
	if len(runs) != 1 || runs[0].RunID != runID || runs[0].AgentName != "agent-"+runID {
		t.Fatalf("ListFirecrackerRuns() = %+v, want exactly run %s reported under its directory name", runs, runID)
	}
	if runs[0].Running {
		t.Errorf("run %s reported running with vm_pid 0", runID)
	}
}

// Liveness is judged under the directory name too: a state file pointing at
// another run's live VMM does not make this run live, and only a VMM
// carrying this run's own ID does.
func TestListFirecrackerRunsLivenessUsesDirectoryName(t *testing.T) {
	runsDir, _ := useTempStateDirs(t)
	const runID, otherID = "76935e132f9be8e9", "aaaaaaaaaaaaaaaa"

	otherPid := startFakeFirecracker(t, otherID)
	writeState(t, filepath.Join(runsDir, runID), fmt.Sprintf(`{"run_id": %q, "vm_pid": %d}`, otherID, otherPid))
	runs := ListFirecrackerRuns()
	if len(runs) != 1 || runs[0].RunID != runID {
		t.Fatalf("ListFirecrackerRuns() = %+v, want exactly run %s", runs, runID)
	}
	if runs[0].Running {
		t.Errorf("run %s reported running on the strength of run %s's VMM (pid %d)", runID, otherID, otherPid)
	}

	ownPid := startFakeFirecracker(t, runID)
	writeState(t, filepath.Join(runsDir, runID), fmt.Sprintf(`{"run_id": %q, "vm_pid": %d}`, runID, ownPid))
	if runs = ListFirecrackerRuns(); len(runs) != 1 || !runs[0].Running {
		t.Errorf("ListFirecrackerRuns() = %+v, want run %s reported running (pid %d)", runs, runID, ownPid)
	}
}

// The abandoned-run sweep runs as root at the start of every run and removes
// stale entries. It may only remove what constle created — entries named
// like a run ID — and must leave anything else under the runs directory
// exactly as found.
func TestCleanupAbandonedFirecrackerIgnoresForeignEntries(t *testing.T) {
	runsDir, _ := useTempStateDirs(t)

	foreign := filepath.Join(runsDir, "not-a-run")
	debris := filepath.Join(runsDir, "0123456789abcdef") // a run that never wrote its state
	mkdirAll(t, foreign, debris)
	backdate(t, foreign, debris)

	cleanupAbandonedFirecracker()

	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("sweep removed %s, which is not named like a run ID and was never constle's to remove: %v", foreign, err)
	}
	if _, err := os.Stat(debris); !os.IsNotExist(err) {
		t.Errorf("sweep left stale run directory %s in place (err=%v)", debris, err)
	}
}

// A run directory without a state file may belong to a Start that is still
// in progress; the sweep leaves it alone until it is old enough to judge.
func TestCleanupAbandonedFirecrackerKeepsYoungDebris(t *testing.T) {
	runsDir, _ := useTempStateDirs(t)
	young := filepath.Join(runsDir, "0123456789abcdef")
	mkdirAll(t, young)

	cleanupAbandonedFirecracker()

	if _, err := os.Stat(young); err != nil {
		t.Errorf("sweep removed a run directory younger than a minute (Start may be racing): %v", err)
	}
}

// The sweep decides which run's resources to destroy by directory name: a
// dead run whose state file borrows a live run's ID and VMM pid is still
// swept, and the live run — its VMM included — is left alone.
func TestCleanupAbandonedFirecrackerUsesDirectoryName(t *testing.T) {
	runsDir, _ := useTempStateDirs(t)
	calls := shimNetTools(t)
	const deadID, liveID = "76935e132f9be8e9", "aaaaaaaaaaaaaaaa"
	livePid := startFakeFirecracker(t, liveID)

	writeState(t, filepath.Join(runsDir, deadID), fmt.Sprintf(`{"run_id": %q, "vm_pid": %d}`, liveID, livePid))
	writeState(t, filepath.Join(runsDir, liveID), fmt.Sprintf(`{"run_id": %q, "vm_pid": %d}`, liveID, livePid))

	cleanupAbandonedFirecracker()

	if _, err := os.Stat(filepath.Join(runsDir, deadID)); !os.IsNotExist(err) {
		t.Errorf("sweep kept dead run %s, whose state file borrowed a live run's identity (err=%v)", deadID, err)
	}
	if _, err := os.Stat(filepath.Join(runsDir, liveID)); err != nil {
		t.Errorf("sweep removed live run %s: %v", liveID, err)
	}
	if !fcProcessAlive(livePid, liveID) {
		t.Errorf("sweep killed the live VMM (pid %d) of run %s", livePid, liveID)
	}
	log := calls()
	if !strings.Contains(log, "ip link del "+fcTAPName(deadID)+"\n") {
		t.Errorf("sweep did not remove the dead run's TAP device; calls:\n%s", log)
	}
	if strings.Contains(log, fcTAPName(liveID)) || strings.Contains(log, nftTableName(liveID)) {
		t.Errorf("sweep touched the live run's TAP device or nftables table; calls:\n%s", log)
	}
}

// StopFirecrackerRun is the path `sudo constle stop` takes. Requires root
// (the function refuses to run otherwise); skipped elsewhere. Everything it
// tears down must belong to the run named on the command line, not to the
// run its state file claims to be.
func TestStopFirecrackerRunUsesDirectoryName(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("StopFirecrackerRun requires root")
	}
	runsDir, jailDir := useTempStateDirs(t)
	calls := shimNetTools(t)
	const runID, otherID = "76935e132f9be8e9", "aaaaaaaaaaaaaaaa"

	writeState(t, filepath.Join(runsDir, runID), fmt.Sprintf(`{"run_id": %q, "vm_pid": 0}`, otherID))
	writeState(t, filepath.Join(runsDir, otherID), fmt.Sprintf(`{"run_id": %q, "vm_pid": 0}`, otherID))
	mkdirAll(t,
		filepath.Join(jailDir, "firecracker", runID, "root"),
		filepath.Join(jailDir, "firecracker", otherID, "root"))

	if err := StopFirecrackerRun(runID); err != nil {
		t.Fatalf("StopFirecrackerRun(%q): %v", runID, err)
	}

	for _, gone := range []string{
		filepath.Join(runsDir, runID),
		filepath.Join(jailDir, "firecracker", runID),
	} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("%s still exists after stop (err=%v)", gone, err)
		}
	}
	for _, kept := range []string{
		filepath.Join(runsDir, otherID),
		filepath.Join(jailDir, "firecracker", otherID),
	} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("stop of run %s removed %s, which belongs to the run the state file claimed: %v", runID, kept, err)
		}
	}
	log := calls()
	for _, want := range []string{
		"ip link del " + fcTAPName(runID) + "\n",
		"nft delete table inet " + nftTableName(runID) + "\n",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("stop did not run %q; calls:\n%s", strings.TrimSpace(want), log)
		}
	}
	if strings.Contains(log, fcTAPName(otherID)) || strings.Contains(log, nftTableName(otherID)) {
		t.Errorf("stop touched run %s's TAP device or nftables table; calls:\n%s", otherID, log)
	}
}
