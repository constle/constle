package a2a

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/constle/constle/internal/filelock"
	"github.com/constle/constle/internal/homedir"
)

// ============================================================
// replay_store.go — the durable half of replay protection
//
// The in-memory seen set in replayGuard dies with the process, which used
// to be a named limitation: a validly signed envelope captured in one run
// could be replayed against a LATER run while still inside the ±5 minute
// timestamp window. This store closes that window by persisting every
// accepted msg_id, keyed by the receiving identity's DID, following the
// spending ledger's durability model exactly: append-only JSONL under the
// invoking user's home, serialized by blocking advisory locks so
// concurrent constle processes of the same identity share one seen set.
//
// Layout: <replayStateRoot>/<sanitized-did>/<UTC hour>.jsonl, plus a
// zero-length "lock" file. Records land in the bucket of the hour they
// were accepted in, and only ever appended — expiry is deleting whole
// bucket files once they can no longer matter, so nothing is rewritten
// and a crash can tear at most the final record of one bucket.
//
// How far back a lookup must reach: check() has already bounded the
// envelope's timestamp to ±replayWindow of now, and its original
// acceptance (if any) happened within replayWindow of that same
// timestamp — so any record that can still reject a replay is younger
// than 2×replayWindow (10 minutes), always inside the current or the
// previous hour bucket. Older buckets exist only to be pruned.
// ============================================================

// replayStateRoot returns the directory holding all per-DID replay state.
// Package variable so this package's tests keep durable state out of the
// real home; resolves through sudo like the spending ledger, because a
// Firecracker (sudo) run and a Docker run of the same identity must share
// one seen set.
var replayStateRoot = func() string {
	return filepath.Join(homedir.InvokingUserHome(), ".constle", "a2a", "replay")
}

// replayStore persists accepted msg_ids for one receiving identity.
type replayStore struct {
	dir string
}

// replayRecord is one accepted envelope. The timestamp is forensic —
// matching is by id alone, and expiry is by bucket file.
type replayRecord struct {
	TS    time.Time `json:"ts"`
	MsgID string    `json:"msg_id"`
}

// openReplayStore opens (creating if needed) the replay directory for one
// identity. Directories go through homedir.MkdirAllOwned so a sudo run
// never leaves root-owned state in the invoking user's home.
func openReplayStore(did string) (*replayStore, error) {
	dir := filepath.Join(replayStateRoot(), sanitizeDID(did))
	if err := homedir.MkdirAllOwned(dir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create a2a replay state directory: %w", err)
	}
	return &replayStore{dir: dir}, nil
}

// sanitizeDID maps a DID to a safe directory name (did:key:z6Mk… →
// did-key-z6Mk…), the spending ledger's rule. Anything outside
// [A-Za-z0-9._-] becomes '-'.
func sanitizeDID(did string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			return r
		default:
			return '-'
		}
	}, did)
}

// bucketHourFormat names bucket files by the UTC hour of acceptance.
const bucketHourFormat = "2006-01-02T15"

func (s *replayStore) bucketPath(t time.Time) string {
	return filepath.Join(s.dir, t.UTC().Format(bucketHourFormat)+".jsonl")
}

// checkAndRecord reports whether msgID was already accepted and, if not,
// records it — one atomic step relative to every other constle process of
// this identity, under an exclusive lock on the store's lock file. (The
// lock file is separate from the buckets because a lookup spans two bucket
// files and the append may create a third; one lock covers them all.)
func (s *replayStore) checkAndRecord(msgID string, now time.Time) (dup bool, err error) {
	lockPath := filepath.Join(s.dir, "lock")
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return false, fmt.Errorf("cannot open a2a replay lock: %w", err)
	}
	// The handle exists only to carry the lock — closing releases it (and
	// is also the unlock backstop), and there is no written data to lose.
	defer func() { _ = lf.Close() }()
	if err := homedir.ChownToInvokingUser(lockPath); err != nil {
		return false, fmt.Errorf("cannot restore a2a replay lock ownership: %w", err)
	}
	if err := filelock.Exclusive(lf); err != nil {
		return false, fmt.Errorf("cannot lock a2a replay state: %w", err)
	}
	defer func() { _ = filelock.Unlock(lf) }()

	for _, path := range []string{s.bucketPath(now), s.bucketPath(now.Add(-time.Hour))} {
		found, err := bucketContains(path, msgID)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}

	if err := s.append(msgID, now); err != nil {
		return false, err
	}
	s.pruneExpired(now)
	return false, nil
}

// bucketContains scans one bucket file for msgID. A line that does not
// parse is skipped, not fatal: a record is written before its envelope is
// accepted, so a torn line (crash mid-append) belongs to a call that was
// never delivered — losing it re-admits at most that one undelivered
// envelope, whereas failing closed here would reject ALL inbound A2A until
// someone deletes the file by hand.
func bucketContains(path, msgID string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("cannot open a2a replay bucket: %w", err)
	}
	// Read-only handle: closing cannot lose data.
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var rec replayRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec.MsgID == msgID {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("cannot read a2a replay bucket %s: %w", path, err)
	}
	return false, nil
}

// append writes one record to the current bucket. Close errors are
// promoted like the spending ledger's: a record that never reached disk is
// a replay the next run would accept, so a deferred write failure must not
// pass silently.
func (s *replayStore) append(msgID string, now time.Time) (err error) {
	path := s.bucketPath(now)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("cannot open a2a replay bucket: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("cannot flush a2a replay bucket: %w", cerr)
		}
	}()
	if err := homedir.ChownToInvokingUser(path); err != nil {
		return fmt.Errorf("cannot restore a2a replay bucket ownership: %w", err)
	}

	line, err := json.Marshal(replayRecord{TS: now.UTC(), MsgID: msgID})
	if err != nil {
		return fmt.Errorf("cannot marshal a2a replay record: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("cannot append to a2a replay bucket: %w", err)
	}
	return nil
}

// pruneExpired deletes bucket files too old to reject anything (see the
// 2×replayWindow bound in the package comment; a whole extra hour of slack
// is kept on top). Best effort under the already-held lock: a bucket that
// survives a failed delete is retried on the next accepted call, and never
// causes a false rejection — msg_ids are random, and a genuine replay of
// its era is already stopped by the timestamp window.
func (s *replayStore) pruneExpired(now time.Time) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	cutoff := now.UTC().Add(-2 * time.Hour).Format(bucketHourFormat)
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".jsonl")
		if !ok {
			continue // the lock file, or something a person put here
		}
		if _, err := time.Parse(bucketHourFormat, name); err != nil {
			continue
		}
		// Bucket names sort chronologically, so a string compare against
		// the cutoff's name is a time compare.
		if name < cutoff {
			_ = os.Remove(filepath.Join(s.dir, e.Name()))
		}
	}
}
