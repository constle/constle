package webhookkey

import (
	"os"
	"path/filepath"
	"testing"
)

// Key generation runs as root under sudo and hands the key directory and
// files back to the invoking user, exactly like identity.Create — and is
// exposed to the same planted-symlink attack. See internal/identity.

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

func TestGenerateRefusesSymlinkedKeyDir(t *testing.T) {
	withTempRoot(t)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, Dir("linked-approver")); err != nil {
		t.Fatal(err)
	}

	if _, err := Generate("linked-approver"); err == nil {
		t.Errorf("Generate followed the planted directory symlink, want an error")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("Generate wrote %q behind the symlink", entries[0].Name())
	}
}

func TestGenerateRefusesSymlinkedMetadataFile(t *testing.T) {
	withTempRoot(t)
	victim := plantVictim(t)
	dir := Dir("meta-approver")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, metaFileName)); err != nil {
		t.Fatal(err)
	}

	if _, err := Generate("meta-approver"); err == nil {
		t.Errorf("Generate wrote %s through the planted symlink, want an error", metaFileName)
	}
	assertUntouched(t, victim)
}
