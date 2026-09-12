package audit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/constle/constle/internal/homedir"
	"github.com/constle/constle/internal/homedir/homedirtest"
)

// The audit logger runs as root under sudo (the Firecracker backend requires
// it) and writes inside the invoking user's home, then hands the file back to
// that user. A symlink the user planted at the log path must therefore never
// be followed — not by the open, and not by the ownership hand-back — or the
// user gets root's write access to (and then ownership of) whatever the link
// points at.

func TestNewRefusesSymlinkedLogFile(t *testing.T) {
	victim := homedirtest.PlantVictim(t)
	loc := homedir.Under(t.TempDir(), "agent-2026-09-12.jsonl")
	logPath := loc.String()
	homedirtest.Symlink(t, victim, logPath)

	logger, err := New(loc)
	if err == nil {
		// Old behavior, for the record: the logger is open on the victim and
		// the first entry lands in it.
		_ = logger.Log("run-1", "agent", EventRunStarted, nil)
		_ = logger.Close()
		t.Errorf("New(%q) followed the planted symlink: got a logger, want an error", logPath)
	} else if !errors.Is(err, homedir.ErrSymlink) {
		t.Errorf("New(%q) error = %v, want homedir.ErrSymlink", logPath, err)
	}
	homedirtest.AssertUntouched(t, victim)
}

func TestNewRefusesSymlinkedLogDir(t *testing.T) {
	elsewhere := t.TempDir()
	base := t.TempDir()
	homedirtest.Symlink(t, elsewhere, filepath.Join(base, "logs"))
	loc := homedir.Under(base, "logs", "agent-2026-09-12.jsonl")
	logPath := loc.String()

	logger, err := New(loc)
	if err == nil {
		_ = logger.Close()
		t.Errorf("New(%q) followed the planted directory symlink: got a logger, want an error", logPath)
	} else if !errors.Is(err, homedir.ErrSymlink) {
		t.Errorf("New(%q) error = %v, want homedir.ErrSymlink", logPath, err)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("New created %q behind the symlink", entries[0].Name())
	}
}
