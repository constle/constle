// Package homedirtest holds helpers for tests that plant symbolic links in
// the trees homedir guards: a stand-in for a root-owned target, a link
// planter that skips where links cannot be made, and the check that the
// target survived.
package homedirtest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const victimContent = "do not touch\n"

// PlantVictim creates a file standing in for a root-owned target such as
// /etc/shadow and returns its path. Its content must survive the test; see
// AssertUntouched.
func PlantVictim(t testing.TB) string {
	t.Helper()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte(victimContent), 0600); err != nil {
		t.Fatal(err)
	}
	return victim
}

// AssertUntouched fails the test when the victim planted by PlantVictim was
// written through a link.
func AssertUntouched(t testing.TB, victim string) {
	t.Helper()
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("victim vanished: %v", err)
	}
	if string(data) != victimContent {
		t.Errorf("victim was written through the symlink: %q", data)
	}
}

// Symlink creates link -> target, or skips the test where symbolic links
// cannot be created (Windows without the SeCreateSymbolicLinkPrivilege or
// Developer Mode) — the property under test needs one to exist.
func Symlink(t testing.TB, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create symbolic links here: %v", err)
		}
		t.Fatal(err)
	}
}
