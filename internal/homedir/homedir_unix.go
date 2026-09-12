//go:build unix

package homedir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
)

// On unix every element of a Location's relative path is opened with
// openat(2) relative to the descriptor of its parent, with O_NOFOLLOW, so a
// symbolic link at any level fails the open instead of being followed — a
// property the kernel enforces at each step, with no window between a check
// and a use for the user to swap a directory for a link. Directories are
// created with mkdirat(2) against the same parent descriptor and handed to
// the invoking user with fchown(2) on the descriptor they were then opened
// through. Only the base directory is opened by pathname, and it is trusted.

// openDir opens base/comps... as a directory, one element at a time.
func openDir(base string, comps []string) (*os.File, error) {
	fd, err := retryEINTR(func() (int, error) {
		return unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	})
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: base, Err: err}
	}
	dir := os.NewFile(uintptr(fd), base)
	for i, c := range comps {
		child, err := openDirAt(dir, c, filepath.Join(append([]string{base}, comps[:i+1]...)...))
		_ = dir.Close()
		if err != nil {
			return nil, err
		}
		dir = child
	}
	return dir, nil
}

// openDirAt opens the directory name inside parent, refusing a symbolic link.
func openDirAt(parent *os.File, name, path string) (*os.File, error) {
	fd, err := retryEINTR(func() (int, error) {
		return unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	})
	if err != nil {
		return nil, classifyOpenError(parent, name, "open", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

// openFile opens the file base/comps... with O_NOFOLLOW at every level.
func openFile(base string, comps []string, flag int, perm os.FileMode) (*os.File, error) {
	parent, err := openDir(base, comps[:len(comps)-1])
	if err != nil {
		return nil, err
	}
	defer func() { _ = parent.Close() }()

	name := comps[len(comps)-1]
	path := filepath.Join(append([]string{base}, comps...)...)
	fd, err := retryEINTR(func() (int, error) {
		// O_NONBLOCK so that a named pipe planted at the target cannot stall
		// the open before the regular-file check below rejects it
		// (O_NOFOLLOW covers links, not pipes). It is cleared again before
		// the descriptor is handed out, so callers get a plain blocking file.
		return unix.Openat(int(parent.Fd()), name, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, uint32(perm.Perm()))
	})
	if err != nil {
		return nil, classifyOpenError(parent, name, "open", path, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	if kind := st.Mode & unix.S_IFMT; kind != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, &fs.PathError{Op: "open", Path: path, Err: fmt.Errorf("not a regular file (%s)", fileKind(uint32(kind)))}
	}
	if err := clearNonblock(fd); err != nil {
		_ = unix.Close(fd)
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// fileKind names the S_IFMT type bits of a non-regular file for an error.
func fileKind(kind uint32) string {
	switch kind {
	case unix.S_IFDIR:
		return "directory"
	case unix.S_IFIFO:
		return "named pipe"
	case unix.S_IFSOCK:
		return "socket"
	case unix.S_IFCHR, unix.S_IFBLK:
		return "device"
	case unix.S_IFLNK:
		return "symbolic link"
	}
	return fmt.Sprintf("mode %#o", kind)
}

// clearNonblock takes fd out of non-blocking mode.
func clearNonblock(fd int) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK)
	return err
}

// mkdirAll creates each missing level of base/comps... and hands every level
// to the invoking user through the descriptor it was opened with.
func mkdirAll(base string, comps []string, perm os.FileMode) error {
	dir, err := openDir(base, nil)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()

	for i, c := range comps {
		path := filepath.Join(append([]string{base}, comps[:i+1]...)...)
		created := false
		child, err := openDirAt(dir, c, path)
		if errors.Is(err, fs.ErrNotExist) {
			// Create it, then open what is there now: a concurrent constle
			// run may have won the race (fine), or the user may have swapped
			// a link in (refused by the O_NOFOLLOW reopen).
			switch err := unix.Mkdirat(int(dir.Fd()), c, uint32(perm.Perm())); {
			case err == nil:
				created = true
			case !errors.Is(err, fs.ErrExist):
				return &fs.PathError{Op: "mkdir", Path: path, Err: err}
			}
			child, err = openDirAt(dir, c, path)
		}
		if err != nil {
			return err
		}
		if err := handOverDir(child, created); err != nil {
			_ = child.Close()
			return err
		}
		_ = dir.Close()
		dir = child
	}
	return nil
}

// readDir lists base/comps... through a descriptor opened with O_NOFOLLOW
// at every level.
func readDir(base string, comps []string) ([]fs.DirEntry, error) {
	dir, err := openDir(base, comps)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	sortDirEntries(entries)
	return entries, nil
}

// remove unlinks the last element of base/comps... relative to its verified
// parent directory. unlinkat never follows a symbolic link at the target.
func remove(base string, comps []string) error {
	parent, err := openDir(base, comps[:len(comps)-1])
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()

	name := comps[len(comps)-1]
	path := filepath.Join(append([]string{base}, comps...)...)
	err = unix.Unlinkat(int(parent.Fd()), name, 0)
	if err == unix.EISDIR || err == unix.EPERM {
		// unlink(2) refuses a directory with EISDIR on Linux and EPERM on
		// the BSDs — but EPERM also means a genuine permission problem, so
		// only retry as a directory removal when the entry really is one.
		var st unix.Stat_t
		if lerr := unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); lerr == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR {
			err = unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
		}
	}
	if err != nil {
		return &fs.PathError{Op: "remove", Path: path, Err: err}
	}
	return nil
}

// classifyOpenError turns the error from an O_NOFOLLOW open into ErrSymlink
// when a symbolic link is what sits at name, and leaves every other error
// alone. Which errno a refused link produces varies by platform (ELOOP on
// Linux and macOS, EMLINK on FreeBSD, EEXIST when O_CREAT|O_EXCL was set),
// so the entry is inspected rather than the errno.
func classifyOpenError(parent *os.File, name, op, path string, err error) error {
	var st unix.Stat_t
	if lerr := unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); lerr == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return symlinkError(op, path)
	}
	return &fs.PathError{Op: op, Path: path, Err: err}
}

// fileOwner reports the uid that owns the file described by fi and its
// hard-link count.
func fileOwner(fi fs.FileInfo) (uid int, nlink uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), uint64(st.Nlink), true
}

// sortDirEntries orders entries by name, matching os.ReadDir, since
// (*os.File).ReadDir returns them in directory order.
func sortDirEntries(entries []fs.DirEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
}

// retryEINTR repeats a descriptor-returning syscall interrupted by a signal,
// as the os package does for its own opens.
func retryEINTR(call func() (int, error)) (int, error) {
	for {
		fd, err := call()
		if err != unix.EINTR {
			return fd, err
		}
	}
}
