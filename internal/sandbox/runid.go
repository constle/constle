package sandbox

import (
	"crypto/rand"
	"fmt"
	"regexp"
)

// ============================================================
// runid.go — run identifiers
//
// A run ID is minted here as 8 random bytes, hex-encoded: exactly 16
// lowercase hex characters. Both backends use it to name everything that
// belongs to the run — Docker containers and networks, and for Firecracker
// the state directory under /var/lib/constle/runs, the jailer chroot and
// the nftables table, all built from the full ID; the TAP device carries
// its first 12 characters (interface names are capped at 15).
//
// That makes the ID a path element, and `constle stop` — which takes it
// from the command line and, for Firecracker, runs as root — must check
// its shape before touching anything: filepath.Join cleans "../" segments
// silently, so an unchecked ID would name a directory anywhere on the host
// as the one to read state from and remove. ValidateRunID is that check;
// it accepts exactly what newRunID produces and nothing else.
// ============================================================

// runIDRE is the exact shape of a run ID as newRunID mints it.
var runIDRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

func newRunID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// ValidateRunID rejects anything that is not exactly what newRunID
// produces: 16 lowercase hex characters. Callers that receive a run ID
// from outside the process — the command line above all — must call it
// before using the ID as a path element, an interface name or a table
// name.
func ValidateRunID(id string) error {
	if !runIDRE.MatchString(id) {
		return fmt.Errorf("invalid run ID %q: must be 16 lowercase hex characters", id)
	}
	return nil
}
