package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// The audit logger runs as root under sudo (the Firecracker backend requires
// it) and writes inside the invoking user's home, then hands the file back to
// that user. A symlink the user planted at the log path must therefore never
// be followed — not by the open, and not by the ownership hand-back — or the
// user gets root's write access to (and then ownership of) whatever the link
// points at.

// plantVictim creates a file standing in for a root-owned target such as
// /etc/shadow and returns its path. Its content and mode must survive the test.
func plantVictim(t *testing.T) string {
	t.Helper()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("do not touch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return victim
}

func assertUntouched(t *testing.T, victim string) {
	t.Helper()
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("victim vanished: %v", err)
	}
	if string(data) != "do not touch\n" {
		t.Errorf("victim was written through the symlink: %q", data)
	}
}

func TestNewRefusesSymlinkedLogFile(t *testing.T) {
	victim := plantVictim(t)
	logPath := filepath.Join(t.TempDir(), "agent-2026-09-12.jsonl")
	if err := os.Symlink(victim, logPath); err != nil {
		t.Fatal(err)
	}

	logger, err := New(logPath)
	if err == nil {
		// Old behavior, for the record: the logger is open on the victim and
		// the first entry lands in it.
		_ = logger.Log("run-1", "agent", EventRunStarted, nil)
		_ = logger.Close()
		t.Errorf("New(%q) followed the planted symlink: got a logger, want an error", logPath)
	}
	assertUntouched(t, victim)
}

func TestNewRefusesSymlinkedLogDir(t *testing.T) {
	elsewhere := t.TempDir()
	base := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(base, "logs")); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(base, "logs", "agent-2026-09-12.jsonl")

	logger, err := New(logPath)
	if err == nil {
		_ = logger.Close()
		t.Errorf("New(%q) followed the planted directory symlink: got a logger, want an error", logPath)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("New created %q behind the symlink", entries[0].Name())
	}
}
