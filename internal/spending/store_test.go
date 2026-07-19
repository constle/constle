package spending

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testStore(t *testing.T) *DailyStore {
	t.Helper()
	return &DailyStore{dir: t.TempDir(), did: "did:key:ztest"}
}

func TestStoreAppendAndTotal(t *testing.T) {
	s := testStore(t)

	total, err := s.TodayTotal()
	if err != nil || total != 0 {
		t.Fatalf("empty store: total=%d err=%v, want 0, nil", total, err)
	}

	if _, err := s.Append("run1", "srv", 300); err != nil {
		t.Fatal(err)
	}
	dayTotal, err := s.Append("run1", "srv", 700)
	if err != nil {
		t.Fatal(err)
	}
	if dayTotal != 1000 {
		t.Errorf("Append returned day total %d, want 1000", dayTotal)
	}

	// A SECOND store handle (a different process, in effect) sees the same
	// durable total.
	s2 := &DailyStore{dir: s.dir, did: s.did}
	total, err = s2.TodayTotal()
	if err != nil {
		t.Fatal(err)
	}
	if total != 1000 {
		t.Errorf("second handle sees %d, want 1000", total)
	}
}

func TestStoreFileIsPerUTCDay(t *testing.T) {
	s := testStore(t)
	if _, err := s.Append("run1", "srv", 1); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(s.dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	if _, err := os.Stat(want); err != nil {
		t.Errorf("expected ledger file %s: %v", want, err)
	}
}

func TestStoreCorruptLedgerFailsClosed(t *testing.T) {
	s := testStore(t)
	if _, err := s.Append("run1", "srv", 5); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.dayPath(), []byte("{not json\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TodayTotal(); err == nil {
		t.Error("corrupt ledger must be an error, never counted as zero spend")
	}
	if _, err := s.Append("run2", "srv", 5); err == nil {
		t.Error("appending over a corrupt ledger must fail, not continue from a wrong total")
	}
}

// TestStoreConcurrentHandles hammers one ledger from many goroutines, each
// with its OWN DailyStore (own file descriptor — flock is per-fd, so this
// exercises real lock contention). Every appended charge must survive and
// the final total must be exact. The true cross-PROCESS version of this
// test lives in internal/sandbox/spending_twoprocess_test.go.
func TestStoreConcurrentHandles(t *testing.T) {
	dir := t.TempDir()
	const workers = 8
	const perWorker = 50
	const amount = MicroCents(7)

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			s := &DailyStore{dir: dir, did: "did:key:ztest"}
			for i := 0; i < perWorker; i++ {
				if _, err := s.Append("run", "srv", amount); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	s := &DailyStore{dir: dir, did: "did:key:ztest"}
	total, err := s.TodayTotal()
	if err != nil {
		t.Fatal(err)
	}
	if want := MicroCents(workers * perWorker * 7); total != want {
		t.Fatalf("total = %d, want exactly %d — concurrent appends lost updates", total, want)
	}
}
