package homedir

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMkdirAllOwnedCreatesNestedDirectories(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "a", "b", "c")

	if err := MkdirAllOwned(dir, 0700); err != nil {
		t.Fatalf("MkdirAllOwned() error: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("dir mode = %04o, want 0700", perm)
	}

	// Idempotent on an existing directory.
	if err := MkdirAllOwned(dir, 0700); err != nil {
		t.Errorf("MkdirAllOwned() on existing dir error: %v", err)
	}
}

func TestChownToInvokingUserIsNoOpWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — the no-op branch is not reachable")
	}
	// Must not fail (or attempt anything) for a normal user.
	if err := ChownToInvokingUser(t.TempDir()); err != nil {
		t.Errorf("ChownToInvokingUser() error: %v", err)
	}
}
