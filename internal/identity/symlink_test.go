package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// Identity creation runs as root under sudo and hands the key directory and
// files back to the invoking user. A symlink the user planted where the
// identity directory or its metadata file will go must be refused, never
// followed: following it would create — and then chown to the user — files
// wherever the link points.

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

func TestCreateRefusesSymlinkedIdentityDir(t *testing.T) {
	withTempRoot(t)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, Dir("linked-agent")); err != nil {
		t.Fatal(err)
	}

	if _, err := Create("linked-agent", ""); err == nil {
		t.Errorf("Create followed the planted directory symlink, want an error")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("Create wrote %q behind the symlink", entries[0].Name())
	}
}

func TestCreateRefusesSymlinkedMetadataFile(t *testing.T) {
	withTempRoot(t)
	victim := plantVictim(t)
	dir := Dir("meta-agent")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, metaFileName)); err != nil {
		t.Fatal(err)
	}

	if _, err := Create("meta-agent", ""); err == nil {
		t.Errorf("Create wrote %s through the planted symlink, want an error", metaFileName)
	}
	assertUntouched(t, victim)
}
