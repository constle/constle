//go:build unix

package sandbox

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/constle/constle/pkg/manifest"
)

// The Firecracker run directory is 0755 by design: `constle ps` reads the
// state file out of it without root (see fcRunState.write). That makes the
// directory mode useless as a confidentiality boundary — every path under it
// is reachable by any local user, so every file must carry its own mode.
//
// The tests below pin the mode of each file the backend creates there. They
// run under umask 0, the most permissive setting an operator's shell can
// have, because O_CREATE's mode argument is only an upper bound: a fix that
// passed 0600 to OpenFile but relied on the umask to get there would pass on
// a machine with umask 077 and leak on one with umask 0.

// withPermissiveUmask clears the umask for the duration of a test, so an
// assertion on a file mode measures the code's intent and not the shell's.
func withPermissiveUmask(t *testing.T) {
	t.Helper()
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("cannot stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// TestRunDirIsTraversableByEveryone is the positive control for the whole
// group: it shows that the run directory itself protects nothing, so the
// per-file assertions that follow are load-bearing rather than belt-and-braces.
// Not a regression test: a positive control. It asserts the premise the
// per-file modes rest on, so it passes both before and after the fix, and it
// builds its own directory rather than tracking what Start chooses.
func TestRunDirIsTraversableByEveryone(t *testing.T) {
	withPermissiveUmask(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatal(err)
	}
	if mode := modeOf(t, runDir); mode&0005 == 0 {
		t.Skip("run directory is no longer world-executable; the per-file modes below are then belt-and-braces")
	}

	// Anything created here with Go's default 0666 lands world-readable.
	f, err := os.Create(filepath.Join(runDir, "control"))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if mode := modeOf(t, filepath.Join(runDir, "control")); mode&0044 == 0 {
		t.Fatalf("control file is %04o, expected world-readable — the premise of these tests no longer holds", mode)
	}
}

// TestBuildWorkspaceImageIsOwnerOnly covers the window between mkfs.ext4 and
// the rename into the 0700 jail. The image carries /env, which holds the
// forwarded API keys and the per-run MCP/A2A gate tokens; os.Create left it
// 0644 in the 0755 run directory for the whole of that window, which is long
// enough for any local user to copy it and read the keys out with debugfs.
//
// The test does exactly that copy-and-read to prove the secret really is in
// the image, then asserts the mode that denies the read.
func TestBuildWorkspaceImageIsOwnerOnly(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 not available")
	}
	withPermissiveUmask(t)

	runDir := filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatal(err)
	}

	const hostKey = "sk-ant-SECRETVALUE-in-the-image"
	const gateToken = "SECRETVALUE-mcp-gate-token"
	t.Setenv("ANTHROPIC_API_KEY", hostKey)

	m := &manifest.AgentManifest{}
	m.Sandbox.Command = []string{"sh", "-c", "true"}

	path, err := buildWorkspaceImage(runDir, m, "172.30.0.1", "172.30.0.2",
		map[string]string{"CONSTLE_MCP_GATE_TOKEN": gateToken})
	if err != nil {
		t.Fatalf("buildWorkspaceImage: %v", err)
	}

	if mode := modeOf(t, path); mode != 0600 {
		t.Errorf("workspace.ext4 is %04o, want 0600 — it sits in a 0755 run directory and carries the run's API keys and gate tokens", mode)
	}

	// Prove the mode is protecting something. debugfs reads the image the
	// same way FirecrackerBackend.Logs does.
	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skip("debugfs not available; mode asserted, contents not verified")
	}
	out, err := exec.Command("debugfs", "-R", "cat /env", path).Output()
	if err != nil {
		t.Fatalf("cannot read /env back out of the image: %v", err)
	}
	for name, secret := range map[string]string{
		"ANTHROPIC_API_KEY":      hostKey,
		"CONSTLE_MCP_GATE_TOKEN": gateToken,
	} {
		if !strings.Contains(string(out), secret) {
			t.Errorf("%s is not in the image's /env, so this test is not exercising the leak it guards", name)
		}
	}
}

// TestOpenConsoleLogIsOwnerOnly pins the serial console capture at 0600.
// It receives VMM diagnostics and the guest init's chatter, and used to
// receive the agent's entire stdout+stderr as well — scripts/guest-init cat'd
// /workspace/agent.log to the console on every run, so a 0644 console.log in
// a 0755 run directory handed the full agent transcript to any local user.
// The echo is gone (the host reads agent.log from the image with debugfs);
// the mode is the second, independent line.
func TestOpenConsoleLogIsOwnerOnly(t *testing.T) {
	withPermissiveUmask(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatal(err)
	}

	f, err := openConsoleLog(runDir)
	if err != nil {
		t.Fatalf("openConsoleLog: %v", err)
	}
	defer func() { _ = f.Close() }()

	if mode := modeOf(t, fcConsoleLogPath(runDir)); mode != 0600 {
		t.Errorf("console.log is %04o, want 0600", mode)
	}
}

// TestOpenConsoleLogTightensAnInheritedMode covers reuse of a run directory
// path: O_CREATE leaves an existing file's mode alone, so a console.log left
// 0666 by an earlier version (or planted by an attacker who won the race to
// create the path) would stay 0666 through O_TRUNC.
func TestOpenConsoleLogTightensAnInheritedMode(t *testing.T) {
	withPermissiveUmask(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fcConsoleLogPath(runDir), []byte("stale\n"), 0666); err != nil {
		t.Fatal(err)
	}

	f, err := openConsoleLog(runDir)
	if err != nil {
		t.Fatalf("openConsoleLog: %v", err)
	}
	defer func() { _ = f.Close() }()

	if mode := modeOf(t, fcConsoleLogPath(runDir)); mode != 0600 {
		t.Errorf("console.log kept the pre-existing mode %04o instead of being tightened to 0600", mode)
	}
}

// TestCreateSquidAccessLogIsNotWorldReadable pins the per-run Squid access
// log at 0640. The log is a complete record of the agent's network activity —
// every host it reached, when, and how many bytes moved — and at 0644 in the
// 0755 run directory it was a live feed of that history to any local user.
//
// It cannot be 0600: Squid has dropped to its own unprivileged user by the
// time it opens the file, so the owner bits belong to that user, and root
// (which runs the flush into the audit log) reads it regardless of mode.
func TestCreateSquidAccessLogIsNotWorldReadable(t *testing.T) {
	withPermissiveUmask(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runDir, "access.log")

	// A user that will not resolve, so the chown is skipped and the test
	// asserts the mode alone — chowning to another user needs root.
	if err := createSquidAccessLog(path, "constle-no-such-user"); err != nil {
		t.Fatalf("createSquidAccessLog: %v", err)
	}

	mode := modeOf(t, path)
	if mode&0007 != 0 {
		t.Errorf("access.log is %04o: world bits are set, so any local user can read the agent's full network history", mode)
	}
	if mode != 0640 {
		t.Errorf("access.log is %04o, want 0640 (owner squid rw, group root r, world nothing)", mode)
	}
	// Squid must still be able to write it after dropping privileges.
	if mode&0200 == 0 {
		t.Errorf("access.log is %04o: the owner cannot write, so Squid would log nothing", mode)
	}
}

// TestGuestInitDoesNotEchoAgentLogToConsole guards the shell side of the same
// leak. The host reads /workspace/agent.log out of the jailed workspace image
// with debugfs (FirecrackerBackend.Logs); the `cat` in finish() existed only
// to mirror the agent's output into console.log, which is the one place it
// could be seen from outside the jail.
func TestGuestInitDoesNotEchoAgentLogToConsole(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "scripts", "guest-init"))
	if err != nil {
		t.Fatalf("cannot read scripts/guest-init: %v", err)
	}

	for _, line := range strings.Split(string(src), "\n") {
		code, _, _ := strings.Cut(line, "#")
		if strings.Contains(code, "agent.log") && strings.Contains(code, "cat") {
			t.Errorf("guest-init still pipes agent.log to the serial console, which lands in a run directory every local user can traverse:\n\t%s", strings.TrimSpace(line))
		}
	}

	// The host path must still exist, or removing the echo would have removed
	// the only way to get the agent's output at all.
	//
	// Searched in CODE only. The comment added above finish() names
	// /workspace/agent.log too, so a whole-file search here is satisfied by
	// the explanation of the fix rather than by the line that still produces
	// the file — it would keep passing with the redirection deleted.
	producer := false
	for _, line := range strings.Split(string(src), "\n") {
		code, _, _ := strings.Cut(line, "#")
		if strings.Contains(code, "> /workspace/agent.log") {
			producer = true
		}
	}
	if !producer {
		t.Error("no line in guest-init redirects the agent's output into /workspace/agent.log; FirecrackerBackend.Logs would have nothing to read")
	}
}

// TestCreateSquidAccessLogTightensAnInheritedMode is the access.log twin of
// TestOpenConsoleLogTightensAnInheritedMode. Without it the Chmod in
// createSquidAccessLog can be deleted with every test still green, while the
// identical line for console.log is guarded — an asymmetry that leaves the
// "a file left by an earlier run keeps its mode" case covered for one file in
// the run directory and not the other.
func TestCreateSquidAccessLogTightensAnInheritedMode(t *testing.T) {
	withPermissiveUmask(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runDir, "access.log")
	if err := os.WriteFile(path, []byte("stale\n"), 0666); err != nil {
		t.Fatal(err)
	}

	if err := createSquidAccessLog(path, "constle-no-such-user"); err != nil {
		t.Fatalf("createSquidAccessLog: %v", err)
	}
	if mode := modeOf(t, path); mode != 0640 {
		t.Errorf("access.log kept the pre-existing mode %04o instead of being tightened to 0640", mode)
	}
}

// TestAccessLogOwnerUsesGroupZero asserts the group choice on every platform
// and every CI runner, which the chown itself cannot be: changing another
// user's file requires root, so TestCreateSquidAccessLogOwnershipAsRoot skips
// on an unprivileged runner and the claim goes unverified precisely where a
// regression would land.
//
// It resolves a real account rather than a fixture, and uses the current user
// when that user's own group is not 0 — which is the case on the GitHub
// runner — so "group 0" is distinguishable from "the user's primary group".
func TestAccessLogOwnerUsesGroupZero(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skipf("cannot resolve the current user: %v", err)
	}
	wantUID, ownGID, err := lookupUserIDs(u.Username)
	if err != nil {
		t.Skipf("cannot resolve %s: %v", u.Username, err)
	}

	uid, gid, err := accessLogOwner(u.Username)
	if err != nil {
		t.Fatalf("accessLogOwner(%s): %v", u.Username, err)
	}
	if uid != wantUID {
		t.Errorf("uid = %d, want %d: Squid drops to this user before it opens the log and must own it", uid, wantUID)
	}
	if gid != 0 {
		t.Errorf("gid = %d, want 0: at 0640 that hands the agent's network history to every member of group %d", gid, gid)
	}
	if ownGID == 0 {
		t.Logf("note: %s's own group is already 0 here, so this host cannot tell the two choices apart", u.Username)
	} else if gid == ownGID {
		t.Errorf("gid = %d is the user's OWN group, not 0", gid)
	}
}

// TestAccessLogOwnerRefusesAnUnknownUser pins the error path: a host with no
// Squid account must not silently fall through to uid 0 / gid 0, which would
// chown the log to root and leave Squid unable to write it.
// Not a regression test: it pins the error path of a helper this commit
// introduces, so there is no pre-fix code for it to fail against.
func TestAccessLogOwnerRefusesAnUnknownUser(t *testing.T) {
	if _, _, err := accessLogOwner("constle-no-such-user"); err == nil {
		t.Error("accessLogOwner accepted an unresolvable user; the caller would chown the log to root:root and Squid would log nothing")
	}
}

// TestCreateSquidAccessLogAppliesTheOwner catches the ownership call being
// deleted from createSquidAccessLog, on the unprivileged runners that are
// every runner CI has. Deleting it used to leave the entire suite green.
//
// It has to go through the seam rather than inspect the file, because the file
// cannot show the difference: the chown is best effort and its error is
// discarded, so an unprivileged run leaves access.log owned by the caller
// whether the chown was refused or never attempted at all. Asserting on
// applyAccessLogOwner directly, as TestAccessLogOwnerIsApplied does, proves
// only that the helper works — not that anything calls it.
//
// The cost of the regression is not disclosure: it is access.log staying
// root-owned, Squid unable to write it, and the run's network history missing
// from the audit log.
func TestCreateSquidAccessLogAppliesTheOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")

	type ownerCall struct{ path, user string }
	var calls []ownerCall
	restore := applyAccessLogOwnerFn
	t.Cleanup(func() { applyAccessLogOwnerFn = restore })
	// EPERM is what the real chown hands an unprivileged caller, so the
	// substitute also pins that createSquidAccessLog still swallows it.
	applyAccessLogOwnerFn = func(p, user string) error {
		calls = append(calls, ownerCall{p, user})
		return syscall.EPERM
	}

	if err := createSquidAccessLog(path, "constle-squid-probe"); err != nil {
		t.Fatalf("createSquidAccessLog returned %v: a refused chown is best effort and must not fail the run", err)
	}

	if len(calls) != 1 {
		t.Fatalf("createSquidAccessLog made %d ownership calls, want exactly 1: the chown is not on this path, so access.log would keep the owner it was created with and Squid could not write it", len(calls))
	}
	if calls[0].path != path || calls[0].user != "constle-squid-probe" {
		t.Errorf("ownership call was (%q, %q), want (%q, %q)", calls[0].path, calls[0].user, path, "constle-squid-probe")
	}
}

// TestAccessLogOwnerIsApplied pins applyAccessLogOwner itself: that it really
// attempts the chown rather than reporting success without trying.
// TestAccessLogOwnerUsesGroupZero pins the choice of owner and
// TestCreateSquidAccessLogOwnershipAsRoot pins the result, but the latter
// skips without root. It deliberately says nothing about the call site, which
// is TestCreateSquidAccessLogAppliesTheOwner's job.
//
// It works unprivileged because chowning a file to root is refused rather than
// ignored: an attempt returns EPERM, and no attempt returns nil.
func TestAccessLogOwnerIsApplied(t *testing.T) {
	withPermissiveUmask(t)
	path := filepath.Join(t.TempDir(), "access.log")
	if err := createSquidAccessLog(path, "constle-no-such-user"); err != nil {
		t.Fatal(err)
	}

	// "root" resolves everywhere and is never the unprivileged test user, so
	// the chown is one only a privileged caller can complete.
	err := applyAccessLogOwner(path, "root")

	if os.Geteuid() == 0 {
		if err != nil {
			t.Fatalf("applyAccessLogOwner as root: %v", err)
		}
		fi, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			t.Skip("no syscall.Stat_t on this platform")
		}
		if st.Uid != 0 || st.Gid != 0 {
			t.Errorf("access.log is %d:%d after the chown, want 0:0", st.Uid, st.Gid)
		}
		return
	}

	if err == nil {
		t.Error("applyAccessLogOwner returned nil as an unprivileged user: the chown was never attempted, so access.log keeps whatever owner it was created with and Squid may be unable to write it")
	}
}

// TestCreateSquidAccessLogOwnershipAsRoot completes the picture that
// TestCreateSquidAccessLogIsNotWorldReadable can only assert half of: the
// chown needs root, so without it the file stays owned by the test user and
// the group choice is never exercised.
//
// Group must be 0, not Squid's own group. On a distro where the squid user
// shares a group with other service accounts, 0640 with that group would be
// readable by every one of them — the same disclosure, one ring further in.
// Not a regression test on an ordinary runner: it needs root and skips
// without it. TestAccessLogOwnerUsesGroupZero and TestAccessLogOwnerIsApplied
// carry its claims where CI can check them.
func TestCreateSquidAccessLogOwnershipAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another user requires root")
	}
	squidUser, err := detectSquidUser()
	if err != nil {
		t.Skipf("no squid user on this host: %v", err)
	}
	wantUID, squidGID, err := lookupUserIDs(squidUser)
	if err != nil {
		t.Skipf("cannot resolve %s: %v", squidUser, err)
	}

	withPermissiveUmask(t)
	path := filepath.Join(t.TempDir(), "access.log")
	if err := createSquidAccessLog(path, squidUser); err != nil {
		t.Fatalf("createSquidAccessLog: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t on this platform")
	}

	if int(st.Uid) != wantUID {
		t.Errorf("access.log is owned by uid %d, want %d (%s) — Squid drops to that user before it opens the log", st.Uid, wantUID, squidUser)
	}
	if st.Gid != 0 {
		t.Errorf("access.log group is %d, want 0; at 0640 that hands the agent's network history to every member of group %d", st.Gid, st.Gid)
	}
	if squidGID == 0 {
		t.Logf("note: %s's own group is already 0 here, so this host cannot distinguish the two choices", squidUser)
	}
	if mode := fi.Mode().Perm(); mode != 0640 {
		t.Errorf("access.log is %04o after the chown, want 0640", mode)
	}
}
