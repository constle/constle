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

// TestParseSuggestionThresholdCountsRunes closes a defect an independent review
// found: the edit distance is counted in runes but was compared against the
// byte length of the written key, so a short non-ASCII key looked long enough
// to justify almost any suggestion.
func TestParseSuggestionThresholdCountsRunes(t *testing.T) {
	// Two runes, eight bytes. Against the byte length a distance of three
	// passed, and the parser answered with "did you mean a2a?".
	_, err := Parse(strictAgentfile("\"\U0001F4A3\U0001F4A3\": 1\n"))
	if err == nil {
		t.Fatal("Parse accepted an unknown key")
	}
	if strings.Contains(err.Error(), "did you mean") {
		t.Errorf("suggested a key for input nothing resembles: %v", err)
	}

	// Genuine typos must still be answered, including short ones where the
	// proportional threshold binds tightest: "mc" is two runes one edit from
	// "mcp", so it sits exactly on the limit and must still suggest.
	for _, tc := range []struct{ written, want string }{
		{"mc", "mcp"},
		{"a2", "a2a"},
		{"kin", "kind"},
	} {
		_, err := Parse(strictAgentfile(tc.written + ": 1\n"))
		if err == nil {
			t.Fatalf("Parse accepted the unknown key %q", tc.written)
		}
		if !strings.Contains(err.Error(), `did you mean "`+tc.want+`"`) {
			t.Errorf("%q lost its suggestion of %q: %v", tc.written, tc.want, err)
		}
	}

	// And a longer typo inside a nested section, for the same reason.
	_, err = Parse(strictAgentfile("mcp:\n  server: []\n"))
	if err == nil {
		t.Fatal("Parse accepted an unknown key")
	}
	if !strings.Contains(err.Error(), `did you mean "servers"`) {
		t.Errorf("a real short typo lost its suggestion: %v", err)
	}
}

// TestParseKeyContainingTheDiagnosticDelimiter closes a second review finding:
// the rewriter split yaml's message on the first " not found in type ", so a
// key legitimately containing that text was truncated and the error named a key
// the author never wrote.
func TestParseKeyContainingTheDiagnosticDelimiter(t *testing.T) {
	_, err := Parse(strictAgentfile("\"x not found in type y\": 1\n"))
	if err == nil {
		t.Fatal("Parse accepted an unknown key")
	}
	if !strings.Contains(err.Error(), `unknown key "x not found in type y"`) {
		t.Errorf("the error must name the key as written, got: %v", err)
	}
	if !strings.Contains(err.Error(), "at the top level") {
		t.Errorf("the section must still be resolved, got: %v", err)
	}
}

// TestParseRejectsTrailingDocument: strictness that stopped at the first
// document would be strictness in name only. A decoder reads one document and
// returns, so everything after a `---` was discarded by exactly the silence
// KnownFields was added to end — including YAML that does not parse, which the
// CLI answered with "is valid".
func TestParseRejectsTrailingDocument(t *testing.T) {
	const doc1 = `apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: strict-agent
`
	tests := []struct {
		name string
		yaml string
		want string // a fragment the error must contain
	}{
		{
			name: "unknown key in the second document",
			yaml: doc1 + "---\ncapabilties: [send_email]\n",
			want: "single YAML document",
		},
		{
			name: "a whole second policy",
			yaml: doc1 + "---\nhuman_gates:\n  enabled: true\n",
			want: "single YAML document",
		},
		{
			name: "malformed second document",
			yaml: doc1 + "---\ncapabilities: [\n",
			want: "after the first document",
		},
		{
			name: "empty first document then content",
			yaml: "---\n---\napiVersion: constle.dev/v1alpha1\n",
			want: "single YAML document",
		},
		{
			name: "empty first document then malformed",
			yaml: "---\n---\ncapabilities: [\n",
			want: "after the first document",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatal("Parse accepted a file whose tail it silently discards")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// TestParseAcceptsDocumentMarkers is the counterweight. `---` and `...` are
// markers on a single document and are ordinary YAML style; rejecting them
// would break manifests that are entirely well-formed.
func TestParseAcceptsDocumentMarkers(t *testing.T) {
	const body = `apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: strict-agent
`
	tests := []struct {
		name string
		yaml string
	}{
		{"leading start marker", "---\n" + body},
		{"trailing end marker", body + "...\n"},
		{"both markers", "---\n" + body + "...\n"},
		{"trailing blank lines", body + "\n\n"},
		{"trailing comment", body + "# done\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("Parse rejected a single well-formed document: %v", err)
			}
			if m.Identity.Name != "strict-agent" {
				t.Errorf("identity.name = %q, want the document to have been read", m.Identity.Name)
			}
		})
	}
}

// TestRawDecoderTextCannotForgeALine covers the one branch of
// describeDecodeProblem that does not compose its own message.
//
// A type mismatch is not an unknown field, so parseUnknownField declines it
// and the decoder's own sentence is passed through. That sentence embeds the
// offending scalar, and yaml.v3 decodes escapes before it formats: a "\n"
// written into an Agentfile string arrives in the error as a real newline.
// The CLI's stderr writer preserves the newlines of an error it is relaying,
// deliberately — so line forgery has to be stopped here, where the untrusted
// value enters the error, which is the same rule the %q sites in this package
// already follow.
func TestRawDecoderTextCannotForgeALine(t *testing.T) {
	const forged = "APPROVED"

	_, err := Parse(strictAgentfile("sandbox:\n  memory_mb: \"\\nAPPROVED\\n\"\n"))
	if err == nil {
		t.Fatal("a string in an int field parsed cleanly, so nothing below is tested")
	}

	got := err.Error()
	// Two premises. The first pins the branch: an unknown-field complaint is
	// rewritten and would never reach the passthrough this test is about.
	if !strings.Contains(got, "cannot unmarshal") {
		t.Fatalf("not the decoder type error this test covers: %q", got)
	}
	// The second pins reachability: yaml.v3 truncates the values it quotes,
	// so a payload that never arrives would leave the check below passing
	// over a message that simply does not contain it.
	if !strings.Contains(got, forged) {
		t.Fatalf("the payload never reached the error, so nothing below is tested: %q", got)
	}

	for _, line := range strings.Split(got, "\n") {
		if strings.TrimSpace(line) == forged {
			t.Errorf("an Agentfile scalar opened a line of its own:\n%s", got)
		}
	}
}
