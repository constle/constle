package manifest

import (
	"fmt"
	"strings"
)

// ValidateAllowedHost checks one sandbox.network.allowed_hosts entry against
// the grammar the egress proxy can enforce: an RFC 1123 hostname — lowercase
// ASCII letters, digits, and hyphens in dot-separated labels of at most 63
// characters, at most 253 in total — optionally prefixed with a single "."
// to match the domain and every subdomain of it (Squid's dstdomain form).
// It returns the reason an entry is refused, without the field path;
// callers add that.
//
// The rule is deliberately narrower than "whatever resolves". Every entry
// is written verbatim into the per-run Squid configuration, and squid.conf
// is a line-oriented format with no quoting or escaping for ACL values: a
// newline ends the directive and starts a new one, whitespace separates
// values, a "#" opening a token begins a comment, a quoted token is a file
// include, and a leading dash is an ACL flag. There is no way to render an
// arbitrary string into that grammar safely, so the string must not be
// arbitrary. Admitting only hostname characters makes the rendered line
// mean exactly the allowlist: "example.com\nhttp_access allow all" is
// refused here instead of becoming a standalone directive that nullifies
// egress control, and "api.example.com 10.1.2.3" is refused instead of
// becoming two entries that the MCP and A2A overlap checks never saw.
//
// Uppercase is refused for the same reason rather than folded. Squid
// matches dstdomain values case-insensitively, but the guards that keep an
// MCP server or the sandbox host out of the allowlist (hostsOverlap,
// isHostLoopbackAlias) compare exactly — so "HOST.DOCKER.INTERNAL" would
// pass those guards and still resolve to the gate transport at the proxy.
// One spelling per host closes that, and matches the id charset used
// elsewhere in this package.
//
// buildSquidConfig (internal/sandbox/docker.go) calls this again before it
// renders, so a manifest built in Go without Validate cannot skip it; a
// change to the grammar here changes what that renderer accepts too.
func ValidateAllowedHost(entry string) error {
	host := strings.TrimPrefix(entry, ".")
	if host == "" {
		return fmt.Errorf("must not be empty")
	}
	if len(host) > 253 {
		return fmt.Errorf("must not exceed 253 characters")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return fmt.Errorf("must not contain empty labels (a doubled, trailing, or second leading dot)")
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q must not exceed 63 characters", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("label %q must not start or end with a hyphen", label)
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			default:
				return fmt.Errorf("contains %q (only lowercase letters, digits, hyphens, and dots are allowed)", r)
			}
		}
	}
	return nil
}

// validateNetwork refuses allowlist entries that are not plain hostnames.
// It runs before the MCP and A2A overlap checks so a malformed entry is
// reported as malformed rather than as an overlap — and so those checks,
// which compare each entry as one host, only ever see one host per entry.
func (m *AgentManifest) validateNetwork() error {
	for i, entry := range m.Sandbox.Network.AllowedHosts {
		if err := ValidateAllowedHost(entry); err != nil {
			return fmt.Errorf(
				"network.allowed_hosts[%d]: invalid entry %q — %w; "+
					"use a bare hostname such as api.example.com or .example.com "+
					"(no scheme, port, path, or whitespace)",
				i, entry, err)
		}
	}
	return nil
}
