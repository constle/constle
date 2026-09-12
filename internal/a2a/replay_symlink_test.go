package a2a

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/constle/constle/internal/homedir/homedirtest"
)

// The replay store is written as root under sudo and handed back to the
// invoking user, like the spending ledger. A symlink planted at the lock
// file, at a bucket file, or at the per-DID directory must be refused.

// freshDID returns a DID no other test invocation has used: the package
// shares one replay root (see TestMain), and a planted link must not still
// be there when the same test runs again under -count.
func freshDID(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("did:key:z%s%d", t.Name(), time.Now().UnixNano())
}

func TestReplayStoreRefusesSymlinkedLock(t *testing.T) {
	victim := homedirtest.PlantVictim(t)
	store, err := openReplayStore(freshDID(t))
	if err != nil {
		t.Fatalf("openReplayStore: %v", err)
	}
	homedirtest.Symlink(t, victim, filepath.Join(store.dir.String(), "lock"))

	if _, err := store.checkAndRecord("msg-1", time.Now()); err == nil {
		t.Errorf("checkAndRecord took the replay lock through the planted symlink, want an error")
	}
	homedirtest.AssertUntouched(t, victim)
}

func TestReplayStoreRefusesSymlinkedBucket(t *testing.T) {
	victim := homedirtest.PlantVictim(t)
	store, err := openReplayStore(freshDID(t))
	if err != nil {
		t.Fatalf("openReplayStore: %v", err)
	}
	now := time.Now()
	homedirtest.Symlink(t, victim, store.bucket(now).String())

	if _, err := store.checkAndRecord("msg-1", now); err == nil {
		t.Errorf("checkAndRecord wrote the bucket through the planted symlink, want an error")
	}
	homedirtest.AssertUntouched(t, victim)
}

func TestOpenReplayStoreRefusesSymlinkedDIDDir(t *testing.T) {
	elsewhere := t.TempDir()
	did := freshDID(t)
	homedirtest.Symlink(t, elsewhere, replayStateRoot().Join(sanitizeDID(did)).String())

	store, err := openReplayStore(did)
	if err == nil {
		// Old behavior, for the record: the lock and bucket land behind the link.
		_, _ = store.checkAndRecord("msg-1", time.Now())
		t.Errorf("openReplayStore followed the planted directory symlink, want an error")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("state was created behind the symlink: %s", entries[0].Name())
	}
}
