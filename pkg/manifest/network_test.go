package manifest

import (
	"strings"
	"testing"
)

func TestValidateAllowedHost(t *testing.T) {
	longLabel := strings.Repeat("a", 63)
	longHost := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) // 253 chars

	accept := []string{
		"api.groq.com",
		".example.com",
		"localhost",
		"host.docker.internal",
		"xn--nxasmq6b.example",
		"10.1.2.3",
		"a",
		"3com.com",
		"my-host.example.com",
		longLabel + ".example.com",
		longHost,
	}
	for _, entry := range accept {
		if err := ValidateAllowedHost(entry); err != nil {
			t.Errorf("ValidateAllowedHost(%q) = %v, want nil", entry, err)
		}
	}

	reject := []struct {
		name  string
		entry string
	}{
		{"empty", ""},
		{"lone dot", "."},
		{"double leading dot", "..example.com"},
		{"trailing dot", "example.com."},
		{"doubled dot", "example..com"},
		{"newline directive injection", "example.com\nhttp_access allow all"},
		{"CRLF directive injection", "example.com\r\nhttp_access allow all"},
		{"bare CR", "example.com\rhttp_access allow all"},
		{"space extra token", "example.com http_access allow all"},
		{"tab extra token", "example.com\thttp_access"},
		{"squid comment", "example.com#comment"},
		{"squid file include", "\"/etc/passwd\""},
		{"squid acl flag", "-n"},
		{"leading dash", "-i"},
		{"uppercase", "EXAMPLE.COM"},
		// Squid matches dstdomain case-insensitively, so a mixed-case
		// spelling would reach the host while isHostLoopbackAlias, which
		// compares exactly, never recognised it.
		{"mixed-case loopback alias", "Host.Docker.Internal"},
		{"backslash continuation", "example.com\\"},
		{"scheme", "https://example.com"},
		{"port", "example.com:443"},
		{"path", "example.com/path"},
		{"glob wildcard", "*.example.com"},
		{"underscore", "exa_mple.com"},
		{"leading hyphen", "-example.com"},
		{"trailing hyphen", "example-.com"},
		{"label too long", strings.Repeat("a", 64) + ".example.com"},
		{"host too long", longHost + "e"},
		{"non-ascii", "b" + string(rune(0xfc)) + "cher.de"},
		{"NUL byte", "example.com\x00"},
		{"unicode line separator", "example.com" + string(rune(0x2028)) + "http_access allow all"},
		{"unicode paragraph separator", "example.com" + string(rune(0x2029)) + "http_access allow all"},
		{"next line NEL", "example.com" + string(rune(0x85)) + "http_access allow all"},
		{"non-breaking space", "example.com" + string(rune(0xa0)) + "http_access"},
		{"form feed", "example.com\fhttp_access"},
		{"vertical tab", "example.com\vhttp_access"},
		{"ipv6 literal", "::1"},
		{"bracketed ipv6 literal", "[::1]"},
		{"invalid utf-8", "example.com\xff"},
	}
	for _, tt := range reject {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAllowedHost(tt.entry); err == nil {
				t.Errorf("ValidateAllowedHost(%q) = nil, want error", tt.entry)
			}
		})
	}
}
