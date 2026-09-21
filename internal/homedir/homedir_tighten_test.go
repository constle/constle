package homedir

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMkdirAllOwnedTightenedRefusesTheBase guards the invariant MkdirAllOwned
// states and MkdirAllOwnedTightened nearly broke: "The base itself is never
// touched."
//
// components() maps an empty relative path to an empty component list, so a
// Location built as Under(base) with no elements reached tightenDir with
// nothing to walk, and the walk's starting point — the base — was what got
// chmod'd. The base is the invoking user's home, or whatever a caller
// substituted for it: narrowing it because a log sits directly in it could cut
// off every other reader of a shared directory.
//
// It must also not become an error. Callers do place a file at the base — the
// mcpgate, a2a, audit and cmd tests all do — and refusing there breaks them
// for no gain, since the log's own mode is what protects its contents.
func TestMkdirAllOwnedTightenedLeavesTheBaseAlone(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}

	if err := Under(base).MkdirAllOwnedTightened(0700); err != nil {
		t.Errorf("MkdirAllOwnedTightened on the base returned %v; a caller with a flat log path must still work", err)
	}

	if mode := modePerm(t, base); mode != 0755 {
		t.Errorf("the base directory was changed to %04o; MkdirAllOwned promises the base is never touched", mode)
	}
}

// TestMkdirAllOwnedTightenedNarrowsOnlyTheNamedLevel pins the other half: the
// directory the caller names is narrowed, and the levels above it — shared
// with callers that ask for their own modes — are left exactly as they were.
func TestMkdirAllOwnedTightenedNarrowsOnlyTheNamedLevel(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, ".constle")
	target := filepath.Join(parent, "logs")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{base, parent, target} {
		if err := os.Chmod(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	if err := Under(base, ".constle", "logs").MkdirAllOwnedTightened(0700); err != nil {
		t.Fatalf("MkdirAllOwnedTightened: %v", err)
	}

	if mode := modePerm(t, target); mode != 0700 {
		t.Errorf("named directory is %04o, want 0700", mode)
	}
	for _, d := range []string{base, parent} {
		if mode := modePerm(t, d); mode != 0755 {
			t.Errorf("%s was changed to %04o; only the named level may be narrowed", d, mode)
		}
	}
}

// TestMkdirAllOwnedTightenedNeverWidens pins the direction. A caller asking
// for 0700 on a directory the operator deliberately set to 0500 must narrow to
// the intersection, not raise it to 0700.
func TestMkdirAllOwnedTightenedNeverWidens(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "strict")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(target, 0700) })

	if err := Under(base, "strict").MkdirAllOwnedTightened(0700); err != nil {
		t.Fatalf("MkdirAllOwnedTightened: %v", err)
	}
	if mode := modePerm(t, target); mode != 0500 {
		t.Errorf("directory was widened from 0500 to %04o", mode)
	}
}

func modePerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("cannot stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}
