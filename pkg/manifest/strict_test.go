package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// strictAgentfile wraps extra YAML in the smallest header that parses, so a
// test case contains only the thing it is about.
func strictAgentfile(extra string) []byte {
	return []byte(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: strict-agent
` + extra)
}

// TestParseRejectsUnknownField is the core of C-36: a key the schema does not
// define must not vanish. Each case is a real weakening — a dropped capability
// list lowers the isolation floor, a dropped gate list disarms an approval —
// and every one of them used to parse, validate, and report clean.
func TestParseRejectsUnknownField(t *testing.T) {
	tests := []struct {
		name     string
		extra    string
		wantKey  string
		wantPath string // as the message renders it
	}{
		{
			name:     "top level",
			extra:    "capabilties:\n  - read_file\n",
			wantKey:  `"capabilties"`,
			wantPath: "at the top level",
		},
		{
			name:     "inside a section",
			extra:    "human_gates:\n  enabld: true\n",
			wantKey:  `"enabld"`,
			wantPath: "in human_gates",
		},
		{
			name:     "inside a nested section",
			extra:    "sandbox:\n  network:\n    allowd_hosts: [example.com]\n",
			wantKey:  `"allowd_hosts"`,
			wantPath: "in sandbox.network",
		},
		{
			name:     "inside a list element",
			extra:    "mcp:\n  servers:\n    - id: email\n      url: \"https://e.example.com/mcp\"\n      toolz: [send_email]\n",
			wantKey:  `"toolz"`,
			wantPath: "in mcp.servers[]",
		},
		{
			name:     "inside a pointer section",
			extra:    "mcp:\n  servers:\n    - id: email\n      url: \"https://e.example.com/mcp\"\n      pricing:\n        metres: []\n",
			wantKey:  `"metres"`,
			wantPath: "in mcp.servers[].pricing",
		},
		{
			name:     "two levels of repetition",
			extra:    "mcp:\n  servers:\n    - id: email\n      url: \"https://e.example.com/mcp\"\n      pricing:\n        meters:\n          - usage_paths: a.b\n            usd_per_unit: \"0.1\"\n",
			wantKey:  `"usage_paths"`,
			wantPath: "in mcp.servers[].pricing.meters[]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strictAgentfile(tt.extra))
			if err == nil {
				t.Fatalf("Parse accepted an unknown key %s", tt.wantKey)
			}
			if !strings.Contains(err.Error(), tt.wantKey) {
				t.Errorf("error must name the key %s, got: %v", tt.wantKey, err)
			}
			if !strings.Contains(err.Error(), tt.wantPath) {
				t.Errorf("error must say %q, got: %v", tt.wantPath, err)
			}
		})
	}
}

// TestParseSuggestsNearestKey: a typo is the reason this check exists, so the
// message has to point at the key that was meant — and stay quiet when it
// cannot, because a wrong suggestion sends the author to edit a correct line.
func TestParseSuggestsNearestKey(t *testing.T) {
	tests := []struct {
		name          string
		extra         string
		wantSuggested string // "" means: must not suggest anything
	}{
		{"one letter missing", "capabilties: []\n", "capabilities"},
		{"transposed letters", "sandbox:\n  netwrok: {}\n", "network"},
		{"abbreviated beyond recognition", "spending:\n  alerts:\n    warn: 80\n", ""},
		{"nothing like any key", "zzzzzzzz: 1\n", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strictAgentfile(tt.extra))
			if err == nil {
				t.Fatal("Parse accepted an unknown key")
			}
			got := err.Error()
			if tt.wantSuggested == "" {
				if strings.Contains(got, "did you mean") {
					t.Errorf("must not guess at a key it cannot place, got: %v", err)
				}
				return
			}
			if !strings.Contains(got, `did you mean "`+tt.wantSuggested+`"`) {
				t.Errorf("want a suggestion of %q, got: %v", tt.wantSuggested, err)
			}
		})
	}
}

// TestParseListsAcceptedKeys: naming the key is not enough on its own — the
// author needs to know what the section does take, without leaving the
// terminal for the spec.
func TestParseListsAcceptedKeys(t *testing.T) {
	_, err := Parse(strictAgentfile("human_gates:\n  enabld: true\n"))
	if err == nil {
		t.Fatal("Parse accepted an unknown key")
	}
	for _, key := range []string{
		"enabled", "require_approval_for", "approval_timeout_seconds",
		"on_timeout", "notify", "approver_pubkey",
	} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("accepted-key list is missing %q, got: %v", key, err)
		}
	}
	// A field the schema hides from YAML must not be advertised as accepted.
	if strings.Contains(err.Error(), "isolationinferred") {
		t.Errorf("a yaml:\"-\" field was listed as accepted: %v", err)
	}
}

// TestParseRejectsCaseVariantKey: yaml.v3 matches a tag exactly, so a
// case-variant key binds nothing. That is the same shape as the case-variant
// JSON-RPC member that let the gate inspect one tool while the upstream ran
// another; here it must be an error rather than a silent drop.
func TestParseRejectsCaseVariantKey(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		wantK string
	}{
		{"lowercased apiVersion", "apiversion: constle.dev/v1alpha1\nkind: AgentManifest\nidentity:\n  name: a\n", `"apiversion"`},
		{"capitalised section", "apiVersion: constle.dev/v1alpha1\nkind: AgentManifest\nidentity:\n  name: a\nHuman_Gates:\n  enabled: true\n", `"Human_Gates"`},
		{"capitalised field", "apiVersion: constle.dev/v1alpha1\nkind: AgentManifest\nidentity:\n  name: a\nhuman_gates:\n  Enabled: true\n", `"Enabled"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("Parse accepted the case-variant key %s", tt.wantK)
			}
			if !strings.Contains(err.Error(), tt.wantK) {
				t.Errorf("error must name %s, got: %v", tt.wantK, err)
			}
		})
	}
}

// TestParseReportsEveryUnknownField: fixing one typo only to be told about the
// next is how an author stops reading the output. yaml.v3 accumulates, so
// report the lot.
func TestParseReportsEveryUnknownField(t *testing.T) {
	_, err := Parse(strictAgentfile(`capabilties: [read_file]
human_gates:
  enabld: true
`))
	if err == nil {
		t.Fatal("Parse accepted two unknown keys")
	}
	got := err.Error()
	if !strings.Contains(got, `"capabilties"`) || !strings.Contains(got, `"enabld"`) {
		t.Errorf("both unknown keys must be reported at once, got: %v", err)
	}
	if !strings.Contains(got, "2 problems") {
		t.Errorf("want the problems counted, got: %v", err)
	}
}

// TestParseAcceptsArbitraryMetadataLabels is the counterweight: KnownFields
// does not descend into a map, and metadata.labels is deliberately open. If
// strict decoding ever started rejecting a label, every manifest using one
// would break for no reason.
func TestParseAcceptsArbitraryMetadataLabels(t *testing.T) {
	m, err := Parse(strictAgentfile(`metadata:
  labels:
    use_case: research
    anything_at_all: yes-really
`))
	if err != nil {
		t.Fatalf("Parse rejected a free-form metadata label: %v", err)
	}
	if m.Metadata.Labels["anything_at_all"] != "yes-really" {
		t.Errorf("labels = %v, want the label preserved", m.Metadata.Labels)
	}
}

// TestParseRejectsIsolationInferredKey: Sandbox.IsolationInferred is set by
// Parse to record where the level came from, and carries yaml:"-" so a
// manifest cannot set it. Under strict decoding writing it is an error, which
// is what stops an Agentfile labelling its own declared level "inferred".
func TestParseRejectsIsolationInferredKey(t *testing.T) {
	for _, key := range []string{"isolation_inferred", "isolationinferred", "IsolationInferred"} {
		if _, err := Parse(strictAgentfile("sandbox:\n  " + key + ": true\n")); err == nil {
			t.Errorf("Parse accepted %q, which the schema hides from YAML", key)
		}
	}
}

// TestParseEmptyAgentfileStillDefaults guards the one behavioural difference
// between yaml.Unmarshal and a Decoder: an empty document returns io.EOF where
// Unmarshal returned nothing at all. An empty Agentfile must still reach
// Validate and be refused for its missing apiVersion, not for an EOF.
func TestParseEmptyAgentfileStillDefaults(t *testing.T) {
	for _, name := range []string{"empty", "comment only", "blank lines"} {
		data := map[string][]byte{
			"empty":        {},
			"comment only": []byte("# nothing here\n"),
			"blank lines":  []byte("\n\n\n"),
		}[name]

		m, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: Parse() error = %v, want nil", name, err)
		}
		if m.Sandbox.MemoryMB != 512 || m.Sandbox.DiskMB != 2048 {
			t.Errorf("%s: sandbox defaults not applied: %+v", name, m.Sandbox)
		}
		if m.Sandbox.Network.Egress != "restricted" {
			t.Errorf("%s: egress = %q, want restricted", name, m.Sandbox.Network.Egress)
		}
		if !m.Sandbox.IsolationInferred {
			t.Errorf("%s: isolation should be marked inferred", name)
		}
		if m.HumanGates.OnTimeout != "abort" || m.HumanGates.ApprovalTimeoutSeconds != 300 {
			t.Errorf("%s: human-gate defaults not applied: %+v", name, m.HumanGates)
		}
		if m.Compliance.AuditLogLevel != "standard" {
			t.Errorf("%s: audit_log_level = %q, want standard", name, m.Compliance.AuditLogLevel)
		}
		if err := m.Validate(); err == nil {
			t.Errorf("%s: an empty Agentfile must still fail validation", name)
		}
	}
}

// TestShippedFixturesParseStrictly holds the repository to its own change.
// spec/agent-manifest.yaml says of itself that it is executable and not
// aspirational; strict decoding is exactly the kind of tightening that can
// quietly falsify that, and the demo and example files with it.
func TestShippedFixturesParseStrictly(t *testing.T) {
	var files []string
	for _, pattern := range []string{
		"../../spec/*.yaml",
		"../../demo/*.yaml",
		"../../examples/*/agent.yaml",
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		files = append(files, matches...)
	}
	if len(files) < 9 {
		t.Fatalf("found only %d shipped manifests (%v) — the globs have gone stale", len(files), files)
	}

	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if _, err := Parse(data); err != nil {
				t.Errorf("shipped manifest no longer parses: %v", err)
			}
		})
	}
}

// TestManifestSectionsCoverTheSchema: the accepted-key lists are derived by
// reflection precisely so they cannot drift from the structs. This asserts the
// walk actually reaches every section, since a section it missed would be
// reported with no key list at all rather than loudly.
func TestManifestSectionsCoverTheSchema(t *testing.T) {
	want := []string{
		"", // the document root
		"a2a",
		"a2a.peers[]",
		"compliance",
		"compliance.geo_restrictions",
		"human_gates",
		"human_gates.notify[]",
		"identity",
		"limits",
		"mcp",
		"mcp.servers[]",
		"mcp.servers[].pricing",
		"mcp.servers[].pricing.meters[]",
		"metadata",
		"sandbox",
		"sandbox.network",
		"spending",
		"spending.alerts",
	}

	got := sortedSectionPaths()
	if len(got) != len(want) {
		t.Fatalf("sections = %v (%d), want %d — a section was added without the walk reaching it", got, len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("section %d = %q, want %q", i, got[i], want[i])
		}
	}
}
