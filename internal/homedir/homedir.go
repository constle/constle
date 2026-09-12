// Package homedir resolves the invoking user's home directory, looking
// through sudo, and performs constle's privileged writes beneath it.
//
// The Firecracker backend requires constle to run as root, but per-user
// state (audit logs, spending ledgers, agent identities, webhook keys, a2a
// replay state) must land in the invoking user's home so every run of an
// agent uses the same state regardless of backend — and must be handed back
// to that user afterwards, or their next non-sudo run finds files it cannot
// write.
//
// That makes ~/.constle a tree the user fully controls while root writes
// into it, so nothing here ever trusts a pathname below the home directory:
// every element of a [Location]'s relative path is opened with O_NOFOLLOW
// relative to a directory descriptor already verified (see homedir_unix.go),
// and ownership is transferred with fchown on the descriptor that was opened
// — never by pathname. A symlink the user plants anywhere on the way to a
// target, whether at the file itself or at one of its parent directories, is
// refused with [ErrSymlink] instead of being followed to wherever it points.
// And only what root itself creates changes hands: a file that already
// existed keeps its owner, since rename(2) would otherwise let the user
// harvest any root-owned file they can move into their tree. Root still
// writes such a file, so one with more than one hard link is refused too:
// constle never links its state files, and with fs.protected_hardlinks
// off the user could have made that inode any root-owned file on the
// filesystem.
package homedir

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrSymlink is returned (wrapped in a *fs.PathError naming the link) when a
// symbolic link sits anywhere on a Location's relative path. Such links are
// refused rather than followed, whatever they point at.
var ErrSymlink = errors.New("refusing to follow symbolic link")

// InvokingUserHome resolves the home directory of the user who actually
// invoked constle, looking through sudo.
func InvokingUserHome() string {
	if os.Geteuid() == 0 {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
			if u, err := user.Lookup(sudoUser); err == nil && u.HomeDir != "" {
				return u.HomeDir
			}
		}
	}
	home, _ := os.UserHomeDir()
	return home
}

// Location names a file or directory as a trusted base directory plus a
// relative path beneath it. Base is taken as-is — the invoking user's home
// in production (it comes from the passwd entry, which the user cannot
// change), a t.TempDir() in tests — and Rel is the part the user could have
// tampered with. Every operation on a Location refuses to traverse a
// symbolic link in Rel and rejects a Rel that would leave Base.
type Location struct {
	Base string
	Rel  string
}

// Under returns the Location for the path elements joined beneath base.
func Under(base string, elem ...string) Location {
	return Location{Base: base, Rel: filepath.Join(elem...)}
}

// Join returns the Location for the path elements joined beneath l.
func (l Location) Join(elem ...string) Location {
	return Location{Base: l.Base, Rel: filepath.Join(append([]string{l.Rel}, elem...)...)}
}

// Dir returns the Location of l's parent directory. The parent of the base
// itself is the base.
func (l Location) Dir() Location {
	rel := filepath.Dir(l.Rel)
	if rel == "." {
		rel = ""
	}
	return Location{Base: l.Base, Rel: rel}
}

// String returns the full path, for display and for read-only callers that
// are not running with privilege.
func (l Location) String() string {
	return filepath.Join(l.Base, l.Rel)
}

// components splits Rel into its path elements, rejecting anything that
// would resolve outside Base lexically. A Rel of "" (the base itself) yields
// no components.
func (l Location) components() ([]string, error) {
	if l.Base == "" {
		return nil, errors.New("homedir: no base directory: the invoking user's home could not be resolved (is $HOME set?)")
	}
	rel := filepath.Clean(l.Rel)
	if rel == "." {
		return nil, nil
	}
	if filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" {
		return nil, fmt.Errorf("homedir: %q is not relative to %s", l.Rel, l.Base)
	}
	comps := strings.Split(rel, string(filepath.Separator))
	for _, c := range comps {
		if c == "" || c == "." || c == ".." {
			return nil, fmt.Errorf("homedir: %q escapes %s", l.Rel, l.Base)
		}
	}
	return comps, nil
}

// OpenFile opens the file at l like os.OpenFile, except that no element of
// l.Rel may be a symbolic link and the result must be a regular file: a
// directory, named pipe, socket or device at the target is refused (on unix
// the open itself is non-blocking, so a pipe cannot stall it first). An
// O_TRUNC in flag is applied by ftruncate on the verified descriptor, after
// the open, so a refused open never truncates anything.
//
// This is the read side; writers that run under sudo use [Location.OpenFileOwned].
func (l Location) OpenFile(flag int, perm os.FileMode) (*os.File, error) {
	comps, err := l.components()
	if err != nil {
		return nil, err
	}
	if len(comps) == 0 {
		return nil, fmt.Errorf("homedir: %s is the base directory, not a file", l.Base)
	}
	f, err := openFile(l.Base, comps, flag&^os.O_TRUNC, perm)
	if err != nil {
		return nil, err
	}
	if flag&os.O_TRUNC != 0 {
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	return f, nil
}

// OpenFileOwned is OpenFile for the privileged writers. When the call
// creates the file (O_CREATE, and nothing was there), the new file is handed
// to the invoking user on its descriptor before it is returned, so state a
// sudo run creates inside the user's home comes back owned by that user.
//
// A file that already existed keeps its owner. Handing over pre-existing
// files too would let the user harvest any root-owned file they can rename
// into their tree — rename(2) needs no permission on the file itself, only
// on the directories — and then read it. The cost is that a file an older
// sudo run left root-owned (before ownership restoration existed) is not
// healed: this run still writes it as root, and the user's next non-sudo
// run reports a permission error on it. A pre-existing file owned by
// anybody other than root or the invoking user, or carrying more than one
// hard link, is refused before anything — a requested O_TRUNC included —
// touches it, since nothing constle wrote could have ended up that way.
func (l Location) OpenFileOwned(flag int, perm os.FileMode) (*os.File, error) {
	if flag&os.O_CREATE != 0 {
		// Create exclusively, so that it is known whether this call made
		// the file; only then is ownership transferred.
		f, err := l.OpenFile(flag|os.O_EXCL, perm)
		if err == nil {
			if err := chownToInvokingUser(f); err != nil {
				// Leave nothing behind: an empty root-owned file here would
				// count as pre-existing for every later run and never be
				// handed over.
				_ = f.Close()
				_ = l.Remove()
				return nil, err
			}
			return f, nil
		}
		if flag&os.O_EXCL != 0 || !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		flag &^= os.O_CREATE
	}
	f, err := l.OpenFile(flag&^os.O_TRUNC, perm)
	if err != nil {
		return nil, err
	}
	if err := refuseForeignOwner(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	if flag&os.O_TRUNC != 0 {
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	return f, nil
}

// ReadFile returns the content of the file at l, opened as OpenFile does.
func (l Location) ReadFile() ([]byte, error) {
	f, err := l.OpenFile(os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	// Read-only: closing cannot lose data.
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// MkdirAllOwned creates the directory at l like os.MkdirAll and hands every
// level of l.Rel — created now or left root-owned by an older sudo run — to
// the invoking user, so a sudo run (the Firecracker backend requires one)
// never leaves root-owned directories inside the user's home. No level may
// be a symbolic link, and each is chowned by the descriptor it was verified
// through. The base itself is never touched.
//
// Unlike files (see OpenFileOwned), pre-existing directories are healed
// when they are root-owned and not writable by group or others: moving a
// directory under a new parent needs write permission on the directory
// itself, so a root-owned directory of normal mode cannot have been renamed
// into the tree by the user the way a file can — it must be an older sudo
// run's leftover. A root-owned directory the user can already write is
// left as it is.
func (l Location) MkdirAllOwned(perm os.FileMode) error {
	comps, err := l.components()
	if err != nil {
		return err
	}
	return mkdirAll(l.Base, comps, perm)
}

// ReadDir lists the directory at l, refusing to reach it through a symbolic
// link. The entries are sorted by filename, like os.ReadDir.
func (l Location) ReadDir() ([]fs.DirEntry, error) {
	comps, err := l.components()
	if err != nil {
		return nil, err
	}
	return readDir(l.Base, comps)
}

// Remove deletes the file or empty directory at l without traversing a
// symbolic link on the way. A symbolic link at l itself is removed, never
// followed.
func (l Location) Remove() error {
	comps, err := l.components()
	if err != nil {
		return err
	}
	if len(comps) == 0 {
		return fmt.Errorf("homedir: refusing to remove the base directory %s", l.Base)
	}
	return remove(l.Base, comps)
}

// chownToInvokingUser transfers ownership of a file this run created to the
// user who invoked constle via sudo, by descriptor. Outside sudo (or for a
// genuine root user) it is a no-op.
func chownToInvokingUser(f *os.File) error {
	st, err := inspect(f)
	if err != nil || !st.underSudo || st.owner == st.uid {
		return err
	}
	return f.Chown(st.uid, st.gid)
}

// handOverDir hands a directory to the invoking user: always when this run
// created it, and otherwise only when it is root-owned and not writable by
// group or others (see MkdirAllOwned for why that means it is an older sudo
// run's leftover and not something the user moved in).
func handOverDir(d *os.File, created bool) error {
	st, err := inspect(d)
	if err != nil || !st.underSudo || st.owner == st.uid {
		return err
	}
	if !created && st.perm&0o022 != 0 {
		return nil
	}
	return d.Chown(st.uid, st.gid)
}

// refuseForeignOwner errors when f, a pre-existing file root is about to
// write under sudo, belongs to anybody other than root or the invoking user
// or has more than one hard link. Outside sudo it is a no-op.
func refuseForeignOwner(f *os.File) error {
	_, err := inspect(f)
	return err
}

// ownership is what inspect learns about an open file under sudo.
type ownership struct {
	underSudo bool // false outside sudo: nothing is checked or changed
	uid, gid  int  // the invoking user, to hand state to
	owner     int  // the uid owning the file
	perm      os.FileMode
}

// inspect resolves the invoking user and the owner of f, refusing a
// third-party owner and, for a regular file, a second hard link.
func inspect(f *os.File) (ownership, error) {
	uid, gid, ok := invokingUser()
	if !ok {
		return ownership{}, nil
	}
	fi, err := f.Stat()
	if err != nil {
		return ownership{}, err
	}
	owner, nlink, known := fileOwner(fi)
	if !known {
		return ownership{}, fmt.Errorf("homedir: cannot determine the owner of %s", f.Name())
	}
	if owner != 0 && owner != uid {
		return ownership{}, fmt.Errorf("homedir: %s is owned by uid %d, neither root nor the invoking user (uid %d): refusing to touch it", f.Name(), owner, uid)
	}
	if !fi.IsDir() && nlink > 1 {
		return ownership{}, fmt.Errorf("homedir: %s has %d hard links: refusing to touch it", f.Name(), nlink)
	}
	return ownership{underSudo: true, uid: uid, gid: gid, owner: owner, perm: fi.Mode().Perm()}, nil
}

// invokingUser reports the uid and gid to hand state back to: the sudo
// caller's, when running as root under sudo. ok is false whenever no
// ownership transfer should happen — not root, not under sudo, or sudo
// invoked by root itself.
func invokingUser() (uid, gid int, ok bool) {
	if os.Geteuid() != 0 {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid == 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

// symlinkError wraps ErrSymlink in a PathError naming the offending link.
func symlinkError(op, path string) error {
	return &fs.PathError{Op: op, Path: path, Err: ErrSymlink}
}
