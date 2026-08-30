package sandbox

import (
	"fmt"
	"strings"
)

// cmdError formats a failed external command without ever losing the cause.
// Host tools (docker, nft, ip, mkfs.ext4, cp) explain their failures on
// stderr, so that output is the error when there is any — but a binary that
// is missing from the host produces no output at all, and dropping the exec
// error there reduces the report to an empty string. That is exactly the
// cross-distro failure mode: a tool this host's distro does not ship must
// fail with "executable file not found", not with nothing.
func cmdError(context string, err error, out []byte) error {
	if msg := strings.TrimSpace(string(out)); msg != "" {
		return fmt.Errorf("%s: %s", context, msg)
	}
	return fmt.Errorf("%s: %w", context, err)
}
