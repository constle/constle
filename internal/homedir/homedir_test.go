package homedir

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/constle/constle/internal/homedir/homedirtest"
)

func TestUnderJoinDirString(t *testing.T) {
	base := filepath.Join("home", "u")
	loc := Under(base, ".constle", "logs")
	if got, want := loc.String(), filepath.Join(base, ".constle", "logs"); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	file := loc.Join("a-2026-09-12.jsonl")
	if got, want := file.Rel, filepath.Join(".constle", "logs", "a-2026-09-12.jsonl"); got != want {
		t.Errorf("Join().Rel = %q, want %q", got, want)
	}
	if got := file.Dir(); got != loc {
		t.Errorf("Dir() = %+v, want %+v", got, loc)
	}
	if got := Under(base).Dir(); got != Under(base) {
		t.Errorf("Dir() of the base = %+v, want the base", got)
	}
	if got := Under(base).Rel; got != "" {
		t.Errorf("Under(base).Rel = %q, want \"\"", got)
	}
}

// A relative path that leaves the base is rejected before anything is
// opened, whatever form the escape takes.
func TestLocationRejectsEscapes(t *testing.T) {
	base := t.TempDir()
	for _, rel := range []string{
		"..",
		filepath.Join("..", "x"),
		filepath.Join("a", "..", "..", "x"),
		base, // absolute
	} {
		loc := Location{Base: base, Rel: rel}
		if err := loc.MkdirAllOwned(0700); err == nil {
			t.Errorf("MkdirAllOwned(%q) succeeded, want an error", rel)
		}
		if _, err := loc.OpenFile(os.O_RDONLY, 0); err == nil {
			t.Errorf("OpenFile(%q) succeeded, want an error", rel)
		}
	}
	if err := (Location{}).MkdirAllOwned(0700); err == nil {
		t.Error("MkdirAllOwned with no base succeeded, want an error")
	} else if !strings.Contains(err.Error(), "$HOME") {
		t.Errorf("no-base error %v does not point at $HOME", err)
	}
	if _, err := Under(base).OpenFile(os.O_RDONLY, 0); err == nil {
		t.Error("OpenFile on the base directory succeeded, want an error")
	}
	if err := Under(base).Remove(); err == nil {
		t.Error("Remove of the base directory succeeded, want an error")
	}
}

func TestMkdirAllOwnedCreatesNestedDirectories(t *testing.T) {
	base := t.TempDir()
	loc := Under(base, "a", "b", "c")

	if err := loc.MkdirAllOwned(0700); err != nil {
		t.Fatalf("MkdirAllOwned() error: %v", err)
	}

	info, err := os.Stat(loc.String())
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", loc)
	}
	if perm := info.Mode().Perm(); perm != 0700 && runtime.GOOS != "windows" {
		t.Errorf("dir mode = %04o, want 0700", perm)
	}

	// Idempotent on an existing directory, and a no-op on the base itself.
	if err := loc.MkdirAllOwned(0700); err != nil {
		t.Errorf("MkdirAllOwned() on existing dir error: %v", err)
	}
	if err := Under(base).MkdirAllOwned(0700); err != nil {
		t.Errorf("MkdirAllOwned() on the base error: %v", err)
	}
}

// A symbolic link at any level below the base is refused — whether it
// points somewhere real, dangles, or would otherwise be a perfectly good
// directory to create into.
func TestMkdirAllOwnedRefusesSymlinkAtEveryLevel(t *testing.T) {
	for _, linkAt := range []string{"a", "a/b", "a/b/c"} {
		t.Run(linkAt, func(t *testing.T) {
			base := t.TempDir()
			elsewhere := t.TempDir()
			link := filepath.Join(base, filepath.FromSlash(linkAt))
			if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
				t.Fatal(err)
			}
			homedirtest.Symlink(t, elsewhere, link)

			err := Under(base, "a", "b", "c").MkdirAllOwned(0700)
			if !errors.Is(err, ErrSymlink) {
				t.Fatalf("MkdirAllOwned() error = %v, want ErrSymlink", err)
			}
			var pe *fs.PathError
			if !errors.As(err, &pe) || pe.Path != link {
				t.Errorf("error names %v, want the link %s", err, link)
			}
			if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
				t.Errorf("created %q behind the link", entries[0].Name())
			}
		})
	}

	t.Run("dangling", func(t *testing.T) {
		base := t.TempDir()
		target := filepath.Join(t.TempDir(), "never-created")
		homedirtest.Symlink(t, target, filepath.Join(base, "a"))
		if err := Under(base, "a", "b").MkdirAllOwned(0700); !errors.Is(err, ErrSymlink) {
			t.Fatalf("MkdirAllOwned() error = %v, want ErrSymlink", err)
		}
		if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the dangling link's target was created (Lstat error %v)", err)
		}
	})
}

func TestMkdirAllOwnedRefusesFileInTheWay(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "a"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	err := Under(base, "a", "b").MkdirAllOwned(0700)
	if err == nil {
		t.Fatal("MkdirAllOwned() through a regular file succeeded, want an error")
	}
	if errors.Is(err, ErrSymlink) {
		t.Errorf("error = %v, want a not-a-directory error, not ErrSymlink", err)
	}
}

func TestOpenFileCreatesAndAppends(t *testing.T) {
	base := t.TempDir()
	if err := Under(base, "d").MkdirAllOwned(0700); err != nil {
		t.Fatal(err)
	}
	loc := Under(base, "d", "f.txt")

	for _, chunk := range []string{"one\n", "two\n"} {
		f, err := loc.OpenFileOwned(os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("OpenFileOwned() error: %v", err)
		}
		if f.Name() != loc.String() {
			t.Errorf("Name() = %q, want %q", f.Name(), loc)
		}
		if _, err := f.WriteString(chunk); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(loc.String())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "one\ntwo\n" {
		t.Errorf("content = %q, want the two appended chunks", data)
	}
	// O_RDONLY sees the same file, and a missing file is a plain not-exist
	// error callers can test for.
	f, err := loc.OpenFile(os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile(O_RDONLY) error: %v", err)
	}
	_ = f.Close()
	if _, err := Under(base, "d", "missing").OpenFile(os.O_RDONLY, 0); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OpenFile of a missing file error = %v, want ErrNotExist", err)
	}
}

func TestOpenFileRefusesSymlinks(t *testing.T) {
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("do not touch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, loc Location, link string) {
		t.Helper()
		for _, flag := range []int{
			os.O_RDONLY,
			os.O_APPEND | os.O_CREATE | os.O_WRONLY,
			os.O_CREATE | os.O_TRUNC | os.O_WRONLY,
			os.O_CREATE | os.O_EXCL | os.O_WRONLY,
		} {
			f, err := loc.OpenFile(flag, 0644)
			if err == nil {
				_ = f.Close()
				t.Fatalf("OpenFile(%#x) followed the link at %s", flag, link)
			}
			if !errors.Is(err, ErrSymlink) {
				t.Errorf("OpenFile(%#x) error = %v, want ErrSymlink", flag, err)
			}
			var pe *fs.PathError
			if !errors.As(err, &pe) || pe.Path != link {
				t.Errorf("error names %v, want the link %s", err, link)
			}
		}
		data, err := os.ReadFile(victim)
		if err != nil || string(data) != "do not touch\n" {
			t.Errorf("victim changed: %q, %v", data, err)
		}
	}

	t.Run("file", func(t *testing.T) {
		base := t.TempDir()
		link := filepath.Join(base, "f")
		homedirtest.Symlink(t, victim, link)
		check(t, Under(base, "f"), link)
	})
	t.Run("directory", func(t *testing.T) {
		base := t.TempDir()
		link := filepath.Join(base, "d")
		homedirtest.Symlink(t, filepath.Dir(victim), link)
		check(t, Under(base, "d", "victim"), link)
	})
	t.Run("dangling", func(t *testing.T) {
		base := t.TempDir()
		link := filepath.Join(base, "f")
		target := filepath.Join(t.TempDir(), "never-created")
		homedirtest.Symlink(t, target, link)
		check(t, Under(base, "f"), link)
		if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("O_CREATE through the dangling link created its target (Lstat error %v)", err)
		}
	})
}

func TestReadFile(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "f"), []byte("content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := Under(base, "f").ReadFile()
	if err != nil || string(data) != "content\n" {
		t.Errorf("ReadFile() = %q, %v", data, err)
	}
	if _, err := Under(base, "missing").ReadFile(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile() of a missing file error = %v, want ErrNotExist", err)
	}
	homedirtest.Symlink(t, filepath.Join(base, "f"), filepath.Join(base, "link"))
	if _, err := Under(base, "link").ReadFile(); !errors.Is(err, ErrSymlink) {
		t.Errorf("ReadFile() through a link error = %v, want ErrSymlink", err)
	}
}

func TestOpenFileRefusesNonRegularFile(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "d"), 0700); err != nil {
		t.Fatal(err)
	}
	f, err := Under(base, "d").OpenFile(os.O_RDONLY, 0)
	if err == nil {
		_ = f.Close()
		t.Fatal("OpenFile(O_RDONLY) on a directory succeeded, want an error")
	}
}

// O_TRUNC is honored — after the open has been verified, so a refused open
// (see TestOpenFileRefusesSymlinks) can never have truncated anything.
func TestOpenFileTruncates(t *testing.T) {
	base := t.TempDir()
	loc := Under(base, "f")
	if err := os.WriteFile(loc.String(), []byte("old content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := loc.OpenFile(os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("new\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	data, _ := os.ReadFile(loc.String())
	if string(data) != "new\n" {
		t.Errorf("content = %q, want the truncated rewrite", data)
	}
}

func TestReadDirAndRemove(t *testing.T) {
	base := t.TempDir()
	dir := Under(base, "d")
	if err := dir.MkdirAllOwned(0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"b", "a"} {
		if err := os.WriteFile(dir.Join(name).String(), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := dir.ReadDir()
	if err != nil {
		t.Fatalf("ReadDir() error: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if got := strings.Join(names, ","); got != "a,b" {
		t.Errorf("ReadDir() = %q, want a,b (sorted)", got)
	}

	if err := dir.Join("a").Remove(); err != nil {
		t.Fatalf("Remove() error: %v", err)
	}
	if _, err := os.Lstat(dir.Join("a").String()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a still exists after Remove: %v", err)
	}

	// An empty directory is removed too; a non-empty one is an error, not a
	// recursive delete.
	if err := dir.Join("sub").MkdirAllOwned(0700); err != nil {
		t.Fatal(err)
	}
	if err := dir.Join("sub").Remove(); err != nil {
		t.Errorf("Remove() of an empty directory error: %v", err)
	}
	if err := dir.Remove(); err == nil {
		t.Error("Remove() of a non-empty directory succeeded, want an error")
	}
	if _, err := os.Lstat(dir.Join("b").String()); err != nil {
		t.Errorf("b was removed along with its parent: %v", err)
	}

	// Through a symlinked directory, neither listing nor removal happens.
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "keep"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	homedirtest.Symlink(t, elsewhere, filepath.Join(base, "link"))
	if _, err := Under(base, "link").ReadDir(); !errors.Is(err, ErrSymlink) {
		t.Errorf("ReadDir() through a link error = %v, want ErrSymlink", err)
	}
	if err := Under(base, "link", "keep").Remove(); !errors.Is(err, ErrSymlink) {
		t.Errorf("Remove() through a link error = %v, want ErrSymlink", err)
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, "keep")); err != nil {
		t.Errorf("file behind the link was removed: %v", err)
	}
	// A link at the target itself is removed, not followed.
	if err := Under(base, "link").Remove(); err != nil {
		t.Errorf("Remove() of the link itself error: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, "keep")); err != nil {
		t.Errorf("removing the link removed its target's content: %v", err)
	}
}

func TestChownToInvokingUserIsNoOpWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — the no-op branch is not reachable")
	}
	f, err := os.CreateTemp(t.TempDir(), "f")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	// Must not fail (or attempt anything) for a normal user.
	if err := chownToInvokingUser(f); err != nil {
		t.Errorf("chownToInvokingUser() error: %v", err)
	}
	if err := refuseForeignOwner(f); err != nil {
		t.Errorf("refuseForeignOwner() error: %v", err)
	}
}

// OpenFileOwned with O_CREATE opens an existing file in place (it is not
// recreated, and O_EXCL from a caller still means what it says).
func TestOpenFileOwnedKeepsExistingFile(t *testing.T) {
	loc := Under(t.TempDir(), "f")
	if err := os.WriteFile(loc.String(), []byte("keep\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := loc.OpenFileOwned(os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFileOwned() on an existing file error: %v", err)
	}
	if _, err := f.WriteString("more\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if data, _ := os.ReadFile(loc.String()); string(data) != "keep\nmore\n" {
		t.Errorf("content = %q, want the existing content kept", data)
	}
	if _, err := loc.OpenFileOwned(os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644); !errors.Is(err, fs.ErrExist) {
		t.Errorf("OpenFileOwned(O_EXCL) on an existing file error = %v, want ErrExist", err)
	}
}
