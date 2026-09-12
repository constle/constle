package manifest

import (
	"strings"
	"testing"
)

// TestValidateRejectsAllowedHostInjection is the regression test for the
// Squid directive-injection hole: before the hostname check existed,
// Validate accepted an allowed_hosts entry carrying a newline, and the
// rendered squid.conf then contained the smuggled text as its own
// directive. Validate must refuse such a manifest outright.
func TestValidateRejectsAllowedHostInjection(t *testing.T) {
	cases := []struct {
		name  string
		entry string
	}{
		{"newline", "example.com\nhttp_access allow all"},
		{"crlf", "example.com\r\nhttp_access allow all"},
		{"space", "example.com http_access allow all"},
		{"file include", "\"/etc/hosts\""},
		{"acl flag", "-n"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			m := &AgentManifest{
				APIVersion: "constle.dev/v1alpha1",
				Kind:       "AgentManifest",
				Identity:   Identity{Name: "injection-test"},
				Sandbox: Sandbox{
					Network: Network{
						Egress:       "restricted",
						AllowedHosts: []string{"api.example.com", tt.entry},
					},
				},
			}
			err := m.Validate()
			if err == nil {
				t.Fatalf("Validate() accepted allowed_hosts entry %q", tt.entry)
			}
			if !strings.Contains(err.Error(), "network.allowed_hosts[1]") {
				t.Errorf("error should name the offending entry, got: %v", err)
			}
		})
	}
}

// TestParseThenValidateRejectsYAMLSmuggledNewline proves the newline
// survives YAML parsing intact — through a double-quoted escape and,
// needing no escape at all, through a literal block scalar — and is caught
// by Validate on the real ParseFile path rather than only when a manifest
// is built in Go.
func TestParseThenValidateRejectsYAMLSmuggledNewline(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"double-quoted escape", `
apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: injection-test
sandbox:
  network:
    egress: restricted
    allowed_hosts:
      - "example.com\nhttp_access allow all"
`},
		{"literal block scalar", `
apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: injection-test
sandbox:
  network:
    egress: restricted
    allowed_hosts:
      - |-
        example.com
        http_access allow all
`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}
			if got := m.Sandbox.Network.AllowedHosts[0]; got != "example.com\nhttp_access allow all" {
				t.Fatalf("YAML did not yield the newline payload; entry = %q", got)
			}
			err = m.Validate()
			if err == nil {
				t.Fatal("Validate() accepted a manifest whose allowed_hosts entry carries a newline")
			}
			if !strings.Contains(err.Error(), "network.allowed_hosts[0]") {
				t.Errorf("error should name the smuggled entry, got: %v", err)
			}
		})
	}
}
