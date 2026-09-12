package a2a

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The replay store is written as root under sudo and handed back to the
// invoking user, like the spending ledger. A symlink planted at the lock
// file, at a bucket file, or at the per-DID directory must be refused.

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

func TestReplayStoreRefusesSymlinkedLock(t *testing.T) {
	victim := plantVictim(t)
	const did = "did:key:zLockSymlink"
	store, err := openReplayStore(did)
	if err != nil {
		t.Fatalf("openReplayStore: %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(store.dir, "lock")); err != nil {
		t.Fatal(err)
	}

	if _, err := store.checkAndRecord("msg-1", time.Now()); err == nil {
		t.Errorf("checkAndRecord took the replay lock through the planted symlink, want an error")
	}
	assertUntouched(t, victim)
}

func TestReplayStoreRefusesSymlinkedBucket(t *testing.T) {
	victim := plantVictim(t)
	const did = "did:key:zBucketSymlink"
	store, err := openReplayStore(did)
	if err != nil {
		t.Fatalf("openReplayStore: %v", err)
	}
	now := time.Now()
	if err := os.Symlink(victim, store.bucketPath(now)); err != nil {
		t.Fatal(err)
	}

	if _, err := store.checkAndRecord("msg-1", now); err == nil {
		t.Errorf("checkAndRecord wrote the bucket through the planted symlink, want an error")
	}
	assertUntouched(t, victim)
}

func TestOpenReplayStoreRefusesSymlinkedDIDDir(t *testing.T) {
	elsewhere := t.TempDir()
	const did = "did:key:zDirSymlink"
	if err := os.Symlink(elsewhere, filepath.Join(replayStateRoot(), sanitizeDID(did))); err != nil {
		t.Fatal(err)
	}

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
