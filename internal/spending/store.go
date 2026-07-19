package spending

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/constle/constle/internal/homedir"
)

// DailyStore is the durable per-DID spending ledger: one append-only JSONL
// file per UTC day under ~/.constle/spending/<did>/. Durability across
// independent `constle run` processes is the whole point — an in-memory
// daily total (like the deliberately per-run A2A replay guard) would reset
// on every exit and enforce nothing.
//
// Concurrency: every read and append holds a flock on the day file, and
// Append recomputes the day total from the file while still holding the
// lock — so two runs of the same DID charging at the same moment serialize,
// and both observe a total that includes the other's charges.
type DailyStore struct {
	dir string
	did string
}

// ledgerRecord is one appended charge.
type ledgerRecord struct {
	TS         time.Time `json:"ts"`
	RunID      string    `json:"run_id"`
	ServerID   string    `json:"server_id"`
	MicroCents int64     `json:"microcents"`
}

// Root returns the base directory that holds all per-DID spending ledgers.
// It resolves through sudo like the audit log: a Firecracker (sudo) run and
// a Docker (non-sudo) run of the same agent must share one ledger.
func Root() string {
	return filepath.Join(homedir.InvokingUserHome(), ".constle", "spending")
}

// OpenDailyStore opens (creating if needed) the ledger directory for one
// DID. Directories are created with homedir.MkdirAllOwned so a sudo run
// never leaves root-owned state in the invoking user's home.
func OpenDailyStore(did string) (*DailyStore, error) {
	if did == "" {
		return nil, fmt.Errorf("daily spending tracking requires the agent's DID")
	}
	dir := filepath.Join(Root(), sanitizeDID(did))
	if err := homedir.MkdirAllOwned(dir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create spending ledger directory: %w", err)
	}
	return &DailyStore{dir: dir, did: did}, nil
}

// StoreAt returns a DailyStore rooted at an explicit directory, bypassing
// the per-DID layout under Root(). Used by tests (a ledger outside the real
// home) and usable by future tooling such as a spending report command.
func StoreAt(dir string) *DailyStore {
	return &DailyStore{dir: dir, did: "explicit"}
}

// sanitizeDID maps a DID to a safe directory name (did:key:z6Mk… →
// did-key-z6Mk…). Anything outside [A-Za-z0-9._-] becomes '-'.
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

// dayPath returns the ledger file for the current UTC day. Computed per
// call so a run that crosses UTC midnight charges into the new day's file.
func (s *DailyStore) dayPath() string {
	return filepath.Join(s.dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
}

// TodayTotal returns the accumulated spend already recorded for the
// current UTC day, across every prior (and concurrent) run of this DID.
func (s *DailyStore) TodayTotal() (MicroCents, error) {
	f, err := os.OpenFile(s.dayPath(), os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("cannot open spending ledger: %w", err)
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		return 0, fmt.Errorf("cannot lock spending ledger: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	return sumLedger(f)
}

// Append records one charge and returns the new day total, both under one
// exclusive flock: the append and the recomputed total are a single atomic
// step relative to every other constle process charging the same DID.
func (s *DailyStore) Append(runID, serverID string, amount MicroCents) (dayTotal MicroCents, err error) {
	if amount < 0 {
		return 0, fmt.Errorf("negative charge %d", amount)
	}
	path := s.dayPath()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return 0, fmt.Errorf("cannot open spending ledger: %w", err)
	}
	defer f.Close()

	// Hand a freshly created (or historically root-owned) ledger back to
	// the invoking user — same healing behavior as audit.New.
	if err := homedir.ChownToInvokingUser(path); err != nil {
		return 0, fmt.Errorf("cannot restore spending ledger ownership: %w", err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return 0, fmt.Errorf("cannot lock spending ledger: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	line, err := json.Marshal(ledgerRecord{
		TS:         time.Now().UTC(),
		RunID:      runID,
		ServerID:   serverID,
		MicroCents: int64(amount),
	})
	if err != nil {
		return 0, fmt.Errorf("cannot marshal ledger record: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return 0, fmt.Errorf("cannot append to spending ledger: %w", err)
	}

	if _, err := f.Seek(0, 0); err != nil {
		return 0, fmt.Errorf("cannot rewind spending ledger: %w", err)
	}
	return sumLedger(f)
}

// sumLedger totals every record in an open ledger file. A corrupt line is
// an error, not a zero: an unreadable ledger must fail closed, never count
// as free budget.
func sumLedger(f *os.File) (MicroCents, error) {
	var total MicroCents
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec ledgerRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return 0, fmt.Errorf("spending ledger %s line %d is corrupt: %v", f.Name(), lineNo, err)
		}
		var err error
		total, err = Add(total, MicroCents(rec.MicroCents))
		if err != nil {
			return 0, err
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("cannot read spending ledger: %w", err)
	}
	return total, nil
}
