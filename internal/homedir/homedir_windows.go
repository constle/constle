//go:build windows

package homedir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Windows has no sudo: constle runs as the invoking user, os.Geteuid reports
// -1, and ownership is never transferred — so a followed link here could
// only ever reach what the user already owns. The same rule still holds for
// consistency: every element of a Location's relative path is checked with
// Lstat and a symbolic link (or a junction, which os reports as an irregular
// file) is refused. The check is by pathname, since the Windows API offers
// no O_NOFOLLOW equivalent through the os package.

// walk verifies that no element of base/comps... is a link and that every
// element but the last is a directory. It stops, without error, at the first
// element that does not exist.
func walk(base string, comps []string) error {
	for i := range comps {
		path := filepath.Join(append([]string{base}, comps[:i+1]...)...)
		fi, err := os.Lstat(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			return symlinkError("open", path)
		}
		if i < len(comps)-1 && !fi.IsDir() {
			return &fs.PathError{Op: "open", Path: path, Err: fmt.Errorf("not a directory")}
		}
	}
	return nil
}

func openFile(base string, comps []string, flag int, perm os.FileMode) (*os.File, error) {
	if err := walk(base, comps); err != nil {
		return nil, err
	}
	path := filepath.Join(append([]string{base}, comps...)...)
	f, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, &fs.PathError{Op: "open", Path: path, Err: fmt.Errorf("not a regular file (%s)", fi.Mode().Type())}
	}
	return f, nil
}

func mkdirAll(base string, comps []string, perm os.FileMode) error {
	for i := range comps {
		path := filepath.Join(append([]string{base}, comps[:i+1]...)...)
		if err := walk(base, comps[:i+1]); err != nil {
			return err
		}
		fi, err := os.Lstat(path)
		switch {
		case err == nil:
			if !fi.IsDir() {
				return &fs.PathError{Op: "mkdir", Path: path, Err: fmt.Errorf("not a directory")}
			}
		case errors.Is(err, fs.ErrNotExist):
			if err := os.Mkdir(path, perm); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
		default:
			return err
		}
	}
	return nil
}

func readDir(base string, comps []string) ([]fs.DirEntry, error) {
	if err := walk(base, comps); err != nil {
		return nil, err
	}
	return os.ReadDir(filepath.Join(append([]string{base}, comps...)...))
}

func remove(base string, comps []string) error {
	if err := walk(base, comps[:len(comps)-1]); err != nil {
		return err
	}
	return os.Remove(filepath.Join(append([]string{base}, comps...)...))
}

// fileOwner has no unix uid to report on Windows; inspect never gets this
// far because invokingUser is false without sudo.
func fileOwner(fs.FileInfo) (int, uint64, bool) {
	return 0, 0, false
}
