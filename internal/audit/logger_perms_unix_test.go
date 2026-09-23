//go:build unix

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/constle/constle/internal/homedir"
)

// The audit log is the permanent copy of everything the per-run Squid access
// log holds — every host an agent reached, when, and how many bytes moved —
// plus every other event of every run. The access log is deleted with the run
// directory; this file is not. Until this was fixed it was written 0644
// inside a 0755 directory, so on any host whose home directory is not itself
// restrictive, the whole history was readable by any local user.
//
// These run under umask 0: the mode argument to O_CREATE is an upper bound
// masked by the umask, so a fix that passed 0600 and relied on the umask to
// get there would pass on one machine and leak on another.

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

// logLoc returns a Location for a log file under a fresh fake home, plus the
// on-disk paths of the file and its directory.
func logLoc(t *testing.T) (homedir.Location, string, string) {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".constle", "logs")
	return homedir.Under(home, ".constle", "logs", "agent-2026-09-20.jsonl"),
		filepath.Join(dir, "agent-2026-09-20.jsonl"), dir
}

// TestNewCreatesOwnerOnlyLog covers a fresh installation.
func TestNewCreatesOwnerOnlyLog(t *testing.T) {
	withPermissiveUmask(t)
	loc, file, dir := logLoc(t)

	l, err := New(loc)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = l.Close() }()

	if mode := modeOf(t, file); mode != 0600 {
		t.Errorf("log file is %04o, want 0600 — it holds the agent's full network history", mode)
	}
	if mode := modeOf(t, dir); mode != 0700 {
		t.Errorf("log directory is %04o, want 0700 — at 0755 the filenames disclose which agents ran on which days", mode)
	}
}

// TestNewTightensPreExistingWorldReadableLog is the case that actually
// matters. The exposure is in the records already on disk: an installation
// that has been running for months has a 0755 directory full of 0644 files,
// and O_CREATE's mode does not touch a file that already exists. Raising the
// mode for new files alone would leave every such host exactly as exposed.
//
// This fails against a fix that only changes the constants.
func TestNewTightensPreExistingWorldReadableLog(t *testing.T) {
	withPermissiveUmask(t)
	loc, file, dir := logLoc(t)

	// Lay down exactly what an older release left behind.
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	const existing = `{"event":"network_allowed","details":{"host":"api.example.com"}}` + "\n"
	if err := os.WriteFile(file, []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}

	l, err := New(loc)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = l.Close() }()

	if mode := modeOf(t, file); mode&0077 != 0 {
		t.Errorf("pre-existing log file is still %04o: every record already written stays readable by any local user", mode)
	}
	if mode := modeOf(t, dir); mode&0077 != 0 {
		t.Errorf("pre-existing log directory is still %04o: the filenames stay listable by any local user", mode)
	}

	// Tightening must not have cost the records it was protecting.
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "api.example.com") {
		t.Error("the existing log content was lost while narrowing the mode")
	}
}

// TestTightenFileNeverLoosens guards the direction of the change, and does it
// by calling tightenFile, which is the part that could get it wrong.
//
// The earlier version of this test drove New() against a 0400 file and
// accepted an error as a pass. That never reached tightenFile at all: opening
// a 0400 file O_RDWR fails first, so the test took its error branch and would
// have passed against a tightenFile rewritten to chmod unconditionally —
// exactly the mutation it exists to catch.
//
// Narrowing through the descriptor keeps the fd usable after the mode no
// longer permits opening the path, which is what makes the real case
// reachable: a log an operator restricted while a run holds it open.
func TestTightenFileNeverLoosens(t *testing.T) {
	withPermissiveUmask(t)
	path := filepath.Join(t.TempDir(), "agent-2026-09-20.jsonl")

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Chmod(0400); err != nil {
		t.Fatal(err)
	}

	if err := tightenFile(f, 0600); err != nil {
		t.Fatalf("tightenFile: %v", err)
	}
	if mode := modeOf(t, path); mode != 0400 {
		t.Errorf("tightenFile widened 0400 to %04o; it must only ever remove bits", mode)
	}
}

// TestTightenFileNarrowsAWiderMode is the other direction: the case the fix
// exists for, asserted on the helper rather than through New().
func TestTightenFileNarrowsAWiderMode(t *testing.T) {
	withPermissiveUmask(t)
	path := filepath.Join(t.TempDir(), "agent-2026-09-20.jsonl")

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if err := tightenFile(f, 0600); err != nil {
		t.Fatalf("tightenFile: %v", err)
	}
	if mode := modeOf(t, path); mode != 0600 {
		t.Errorf("tightenFile left the log at %04o, want 0600", mode)
	}
}
