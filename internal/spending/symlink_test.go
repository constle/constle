package spending

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The spending ledger is written as root under sudo and then handed back to
// the invoking user, so a symlink planted at the ledger path — or at any
// directory on the way to it — must be refused, never followed.

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

func TestAppendRefusesSymlinkedLedger(t *testing.T) {
	victim := plantVictim(t)
	dir := t.TempDir()
	today := filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	if err := os.Symlink(victim, today); err != nil {
		t.Fatal(err)
	}

	s := StoreAt(dir)
	if _, err := s.Append("run-1", "srv", 5); err == nil {
		t.Errorf("Append followed the planted symlink at %q, want an error", today)
	}
	assertUntouched(t, victim)
	if _, err := s.TodayTotal(); err == nil {
		t.Errorf("TodayTotal read through the planted symlink at %q, want an error", today)
	}
}

// Every directory level between the user's home and the ledger is under the
// user's control, so a symlink at any of them is refused too.
func TestOpenDailyStoreRefusesSymlinkedLedgerDir(t *testing.T) {
	if os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		t.Skip("under sudo the home directory comes from the passwd entry, not $HOME")
	}
	const did = "did:key:zSymlinkTest"
	for _, link := range []string{
		".constle",
		filepath.Join(".constle", "spending"),
		filepath.Join(".constle", "spending", sanitizeDID(did)),
	} {
		t.Run(link, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			elsewhere := t.TempDir()
			if err := os.MkdirAll(filepath.Dir(filepath.Join(home, link)), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, filepath.Join(home, link)); err != nil {
				t.Fatal(err)
			}

			store, err := OpenDailyStore(did)
			if err == nil {
				// Old behavior, for the record: the ledger lands behind the link.
				_, _ = store.Append("run-1", "srv", 5)
				t.Errorf("OpenDailyStore followed the symlink at ~/%s, want an error", link)
			}
			var created []string
			_ = filepath.WalkDir(elsewhere, func(path string, d os.DirEntry, err error) error {
				if err == nil && path != elsewhere {
					created = append(created, path)
				}
				return nil
			})
			if len(created) != 0 {
				t.Errorf("state was created behind the symlink: %v", created)
			}
		})
	}
}
