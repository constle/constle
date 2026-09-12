package identity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/constle/constle/internal/homedir/homedirtest"
)

// Identity creation runs as root under sudo and hands the key directory and
// files back to the invoking user. A symlink the user planted where the
// identity directory or its metadata file will go must be refused, never
// followed: following it would create — and then chown to the user — files
// wherever the link points.

func TestCreateRefusesSymlinkedIdentityDir(t *testing.T) {
	withTempRoot(t)
	elsewhere := t.TempDir()
	homedirtest.Symlink(t, elsewhere, Dir("linked-agent"))

	if _, err := Create("linked-agent", ""); err == nil {
		t.Errorf("Create followed the planted directory symlink, want an error")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("Create wrote %q behind the symlink", entries[0].Name())
	}
}

func TestCreateRefusesSymlinkedMetadataFile(t *testing.T) {
	withTempRoot(t)
	victim := homedirtest.PlantVictim(t)
	dir := Dir("meta-agent")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	homedirtest.Symlink(t, victim, filepath.Join(dir, metaFileName))

	if _, err := Create("meta-agent", ""); err == nil {
		t.Errorf("Create wrote %s through the planted symlink, want an error", metaFileName)
	}
	homedirtest.AssertUntouched(t, victim)
}
