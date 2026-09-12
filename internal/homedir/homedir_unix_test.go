//go:build unix

package homedir

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A named pipe at the target is refused, not opened: O_NOFOLLOW does not
// cover pipes, and a plain open of one would block until the other end
// appeared — with a root run stuck behind it.
func TestOpenFileRefusesNamedPipe(t *testing.T) {
	base := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(base, "p"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []int{os.O_RDONLY, os.O_WRONLY, os.O_APPEND | os.O_CREATE | os.O_RDWR} {
		done := make(chan error, 1)
		go func() {
			f, err := Under(base, "p").OpenFile(flag, 0644)
			if err == nil {
				_ = f.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("OpenFile(%#x) on a named pipe succeeded, want a refusal", flag)
			} else if errors.Is(err, ErrSymlink) {
				t.Errorf("OpenFile(%#x) error = %v, want a not-a-regular-file error", flag, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("OpenFile(%#x) on a named pipe blocked instead of refusing it", flag)
		}
	}
}

// The creation mode reaches the kernel exactly as os.OpenFile would pass
// it (subject to the umask), since openat takes the same mode argument.
func TestOpenFileAppliesModeUnderUmask(t *testing.T) {
	loc := Under(t.TempDir(), "f")
	f, err := loc.OpenFile(os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	fi, err := os.Stat(loc.String())
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0644&^umask(t) {
		t.Errorf("mode = %04o, want 0644 less the umask", perm)
	}
}

// umask reports the process umask without changing it, so mode expectations
// hold under whatever umask the test runs with.
func umask(t *testing.T) os.FileMode {
	t.Helper()
	old := syscall.Umask(0)
	syscall.Umask(old)
	return os.FileMode(old)
}

// TestSudoHandsStateToInvokingUser exercises the real ownership transfer.
// It only runs as root under sudo (`sudo -E go test ./internal/homedir/`),
// which is how the Firecracker backend runs constle; everywhere else it is
// skipped, so the property is verified by hand rather than in CI.
func TestSudoHandsStateToInvokingUser(t *testing.T) {
	uid, gid, ok := invokingUser()
	if !ok {
		t.Skip("not running as root under sudo")
	}
	owner := func(path string) (int, int) {
		t.Helper()
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		return int(st.Uid), int(st.Gid)
	}
	base := t.TempDir()

	// Every created level ends up the invoking user's; the base is untouched.
	if err := Under(base, "a", "b").MkdirAllOwned(0755); err != nil {
		t.Fatalf("MkdirAllOwned() error: %v", err)
	}
	for _, p := range []string{filepath.Join(base, "a"), filepath.Join(base, "a", "b")} {
		if u, g := owner(p); u != uid || g != gid {
			t.Errorf("%s owned by %d:%d, want %d:%d", p, u, g, uid, gid)
		}
	}
	if u, _ := owner(base); u != 0 {
		t.Errorf("base owned by %d, want root (never touched)", u)
	}

	// A file this call creates is handed over — with or without O_EXCL from
	// the caller.
	for _, tc := range []struct {
		name string
		flag int
	}{
		{"new", os.O_CREATE | os.O_WRONLY},
		{"new-excl", os.O_CREATE | os.O_EXCL | os.O_WRONLY},
		{"new-append", os.O_APPEND | os.O_CREATE | os.O_RDWR},
	} {
		f, err := Under(base, "a", "b", tc.name).OpenFileOwned(tc.flag, 0644)
		if err != nil {
			t.Fatalf("OpenFileOwned(%s) error: %v", tc.name, err)
		}
		_ = f.Close()
		if u, g := owner(filepath.Join(base, "a", "b", tc.name)); u != uid || g != gid {
			t.Errorf("%s owned by %d:%d, want %d:%d", tc.name, u, g, uid, gid)
		}
	}

	// A root-owned file that already existed is written as root but keeps
	// its owner: rename(2) needs no permission on a file, so healing it
	// would hand the user any root-owned file they can move into the tree.
	old := filepath.Join(base, "a", "b", "old")
	if err := os.WriteFile(old, []byte("secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []int{os.O_WRONLY, os.O_APPEND | os.O_CREATE | os.O_RDWR} {
		f, err := Under(base, "a", "b", "old").OpenFileOwned(flag, 0644)
		if err != nil {
			t.Fatalf("OpenFileOwned(%#x) on a root-owned file error: %v", flag, err)
		}
		_ = f.Close()
		if u, _ := owner(old); u != 0 {
			t.Errorf("pre-existing root-owned file was handed over (owner %d), want root kept", u)
		}
	}

	// A file owned by a third user is refused, not silently written,
	// truncated or re-owned — O_TRUNC included.
	third := filepath.Join(base, "a", "b", "third")
	if err := os.WriteFile(third, []byte("theirs\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(third, uid+1, gid); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []int{os.O_WRONLY, os.O_APPEND | os.O_CREATE | os.O_RDWR, os.O_CREATE | os.O_TRUNC | os.O_WRONLY} {
		if f, err := Under(base, "a", "b", "third").OpenFileOwned(flag, 0644); err == nil {
			_ = f.Close()
			t.Errorf("OpenFileOwned(%#x) on a file owned by uid %d succeeded, want a refusal", flag, uid+1)
		} else if !strings.Contains(err.Error(), strconv.Itoa(uid+1)) {
			t.Errorf("refusal %v does not name the owner", err)
		}
	}
	if u, _ := owner(third); u != uid+1 {
		t.Errorf("third-party file owner changed to %d", u)
	}
	if data, _ := os.ReadFile(third); string(data) != "theirs\n" {
		t.Errorf("third-party file content = %q, want it untouched", data)
	}

	// A pre-existing root-owned file with a second hard link is refused:
	// constle never links its state files, so the user chose that inode.
	linked := filepath.Join(base, "a", "b", "linked")
	if err := os.WriteFile(linked, []byte("root's\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(linked, filepath.Join(base, "a", "b", "linked-twin")); err != nil {
		t.Fatal(err)
	}
	if f, err := Under(base, "a", "b", "linked").OpenFileOwned(os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		_ = f.Close()
		t.Error("OpenFileOwned() on a hard-linked root-owned file succeeded, want a refusal")
	} else if !strings.Contains(err.Error(), "hard links") {
		t.Errorf("refusal %v does not mention hard links", err)
	}

	// A root-owned directory of normal mode that already existed is healed;
	// one the user can already write (group/other write bit) is left alone.
	for _, tc := range []struct {
		name string
		mode os.FileMode
		want int
	}{
		{"legacy", 0755, uid},
		{"open", 0777, 0},
	} {
		d := filepath.Join(base, tc.name)
		if err := os.Mkdir(d, tc.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, tc.mode); err != nil { // past the umask
			t.Fatal(err)
		}
		if err := Under(base, tc.name, "sub").MkdirAllOwned(0755); err != nil {
			t.Fatalf("MkdirAllOwned() under %s error: %v", tc.name, err)
		}
		if u, _ := owner(d); u != tc.want {
			t.Errorf("pre-existing %04o directory owned by %d, want %d", tc.mode, u, tc.want)
		}
		if u, _ := owner(filepath.Join(d, "sub")); u != uid {
			t.Errorf("created subdirectory of %s owned by %d, want %d", tc.name, u, uid)
		}
	}
}
