package webhookkey

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/constle/constle/internal/homedir/homedirtest"
)

// Key generation runs as root under sudo and hands the key directory and
// files back to the invoking user, exactly like identity.Create — and is
// exposed to the same planted-symlink attack. See internal/identity.

func TestGenerateRefusesSymlinkedKeyDir(t *testing.T) {
	withTempRoot(t)
	elsewhere := t.TempDir()
	homedirtest.Symlink(t, elsewhere, Dir("linked-approver"))

	if _, err := Generate("linked-approver"); err == nil {
		t.Errorf("Generate followed the planted directory symlink, want an error")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("Generate wrote %q behind the symlink", entries[0].Name())
	}
}

func TestGenerateRefusesSymlinkedMetadataFile(t *testing.T) {
	withTempRoot(t)
	victim := homedirtest.PlantVictim(t)
	dir := Dir("meta-approver")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	homedirtest.Symlink(t, victim, filepath.Join(dir, metaFileName))

	if _, err := Generate("meta-approver"); err == nil {
		t.Errorf("Generate wrote %s through the planted symlink, want an error", metaFileName)
	}
	homedirtest.AssertUntouched(t, victim)
}
