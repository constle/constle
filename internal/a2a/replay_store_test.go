package a2a

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMain points the durable replay store at a throwaway directory for the
// whole package: every gate New() constructs opens a real store, and unit
// tests must never leave state in the developer's actual home.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "constle-a2a-replay-*")
	if err != nil {
		panic(err)
	}
	replayStateRoot = func() string { return dir }
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// TestReplayGuardSurvivesRestart is the cross-run property this store
// exists for: a second guard — a fresh process in miniature, no shared
// memory — rejects an envelope the first guard accepted.
func TestReplayGuardSurvivesRestart(t *testing.T) {
	alice := newTestSigner(t, 1)
	bobDID := newTestSigner(t, 2).DID()

	store1, err := openReplayStore(bobDID)
	if err != nil {
		t.Fatalf("openReplayStore: %v", err)
	}

	wire, _, err := Seal(alice, bobDID, "", []byte(`{"n":1}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env, err := Open(wire)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := newReplayGuard(store1).check(env); err != nil {
		t.Fatalf("first delivery rejected: %v", err)
	}

	// "Restart": a brand-new store handle and guard over the same identity.
	store2, err := openReplayStore(bobDID)
	if err != nil {
		t.Fatalf("openReplayStore (second run): %v", err)
	}
	replayed, err := Open(wire)
	if err != nil {
		t.Fatalf("Open (replay): %v", err)
	}
	assertReject(t, newReplayGuard(store2).check(replayed), ReasonReplay)

	// A fresh envelope still passes in the second run.
	wire2, _, err := Seal(alice, bobDID, "", []byte(`{"n":2}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env2, _ := Open(wire2)
	if err := newReplayGuard(store2).check(env2); err != nil {
		t.Fatalf("fresh envelope rejected after a replay: %v", err)
	}
}

// TestReplayStoreHourBoundary pins the two-bucket lookup: a record written
// late in one hour must still reject early in the next, when the current
// bucket file is a different one.
func TestReplayStoreHourBoundary(t *testing.T) {
	store, err := openReplayStore("did:key:zBoundary")
	if err != nil {
		t.Fatalf("openReplayStore: %v", err)
	}

	accepted := time.Date(2026, 8, 30, 13, 59, 0, 0, time.UTC)
	replayedAt := time.Date(2026, 8, 30, 14, 2, 0, 0, time.UTC)

	if dup, err := store.checkAndRecord("boundary-id", accepted); err != nil || dup {
		t.Fatalf("first record: dup=%v err=%v", dup, err)
	}
	dup, err := store.checkAndRecord("boundary-id", replayedAt)
	if err != nil {
		t.Fatalf("checkAndRecord across hour boundary: %v", err)
	}
	if !dup {
		t.Error("record from the previous hour's bucket was not found")
	}
}

// TestReplayStorePrunesExpiredBuckets verifies old bucket files are removed
// once they can no longer reject anything, so the store stays bounded.
func TestReplayStorePrunesExpiredBuckets(t *testing.T) {
	store, err := openReplayStore("did:key:zPrune")
	if err != nil {
		t.Fatalf("openReplayStore: %v", err)
	}

	now := time.Date(2026, 8, 30, 14, 0, 0, 0, time.UTC)
	stale := store.bucketPath(now.Add(-3 * time.Hour))
	if err := os.WriteFile(stale, []byte(`{"ts":"2026-08-30T11:00:00Z","msg_id":"old"}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fresh := store.bucketPath(now.Add(-time.Hour))
	if err := os.WriteFile(fresh, []byte(`{"ts":"2026-08-30T13:30:00Z","msg_id":"recent"}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := store.checkAndRecord("trigger-prune", now); err != nil {
		t.Fatalf("checkAndRecord: %v", err)
	}

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("expired bucket %s was not pruned (err=%v)", stale, err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("previous-hour bucket %s must survive pruning: %v", fresh, err)
	}
}

// TestReplayStoreSkipsTornRecord: a truncated final line (crash mid-append)
// must not brick the store — later ids are still checked and recorded.
func TestReplayStoreSkipsTornRecord(t *testing.T) {
	store, err := openReplayStore("did:key:zTorn")
	if err != nil {
		t.Fatalf("openReplayStore: %v", err)
	}
	now := time.Date(2026, 8, 30, 14, 30, 0, 0, time.UTC)

	if dup, err := store.checkAndRecord("intact-id", now); err != nil || dup {
		t.Fatalf("first record: dup=%v err=%v", dup, err)
	}
	// Simulate the crash: a torn half-record at the end of the bucket.
	f, err := os.OpenFile(store.bucketPath(now), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"ts":"2026-08-30T14:3`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if dup, err := store.checkAndRecord("intact-id", now); err != nil || !dup {
		t.Fatalf("intact record before the torn line must still match: dup=%v err=%v", dup, err)
	}
	if dup, err := store.checkAndRecord("post-crash-id", now); err != nil || dup {
		t.Fatalf("new id after a torn line: dup=%v err=%v", dup, err)
	}
}

// TestReplayGuardFailsClosedWhenStoreUnavailable: an unusable store rejects
// with replay_guard_unavailable rather than admitting unverifiable input.
func TestReplayGuardFailsClosedWhenStoreUnavailable(t *testing.T) {
	// A store whose directory is actually a file: every open under it fails.
	base := t.TempDir()
	notADir := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(notADir, nil, 0644); err != nil {
		t.Fatal(err)
	}
	guard := newReplayGuard(&replayStore{dir: filepath.Join(notADir, "x")})

	alice := newTestSigner(t, 1)
	wire, _, err := Seal(alice, newTestSigner(t, 2).DID(), "", []byte(`{"n":1}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env, err := Open(wire)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	assertReject(t, guard.check(env), ReasonGuardUnavailable)
}
