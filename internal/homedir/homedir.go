// Package homedir resolves the invoking user's home directory, looking
// through sudo. The Firecracker backend requires constle to run as root, but
// per-user state (audit logs, agent identities) must land in the invoking
// user's home so every run of an agent uses the same state regardless of
// backend.
package homedir

import (
	"os"
	"os/user"
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
