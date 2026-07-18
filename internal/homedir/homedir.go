// Package homedir resolves the invoking user's home directory, looking
// through sudo. The Firecracker backend requires constle to run as root, but
// per-user state (audit logs, agent identities) must land in the invoking
// user's home so every run of an agent uses the same state regardless of
// backend.
package homedir

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

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

// ChownToInvokingUser transfers ownership of the given paths to the user who
// invoked constle via sudo. Outside sudo (or for a genuine root user) it is
// a no-op. Per-user state written by a sudo run — audit logs, identities —
// must end up owned by the invoking user, or their next non-sudo command
// finds files it cannot write (or, for keys, read).
func ChownToInvokingUser(paths ...string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid == 0 {
		return nil
	}
	for _, p := range paths {
		if err := os.Chown(p, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

// MkdirAllOwned creates dir like os.MkdirAll and hands every directory level
// it actually created back to the invoking sudo user, so a sudo run (the
// Firecracker backend requires one) never leaves root-owned directories
// inside the user's home. Pre-existing ancestors are left untouched.
func MkdirAllOwned(dir string, perm os.FileMode) error {
	var created []string
	for p := dir; ; {
		if _, err := os.Stat(p); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return err
		}
		created = append(created, p)
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}

	if err := os.MkdirAll(dir, perm); err != nil {
		return err
	}
	return ChownToInvokingUser(created...)
}
