package spending

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/constle/constle/internal/homedir/homedirtest"
)

// The spending ledger is written as root under sudo and then handed back to
// the invoking user, so a symlink planted at the ledger path — or at any
// directory on the way to it — must be refused, never followed.

func TestAppendRefusesSymlinkedLedger(t *testing.T) {
	victim := homedirtest.PlantVictim(t)
	dir := t.TempDir()
	today := filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	homedirtest.Symlink(t, victim, today)

	s := StoreAt(dir)
	if _, err := s.Append("run-1", "srv", 5); err == nil {
		t.Errorf("Append followed the planted symlink at %q, want an error", today)
	}
	homedirtest.AssertUntouched(t, victim)
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
			homedirtest.Symlink(t, elsewhere, filepath.Join(home, link))

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
