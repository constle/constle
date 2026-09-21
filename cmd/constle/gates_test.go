package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/constle/constle/pkg/manifest"
)

// withCapturedGatesWarn redirects warnUnenforcedHumanGates output into a
// buffer for the duration of one test, restoring the writer afterwards.
func withCapturedGatesWarn(t *testing.T) *bytes.Buffer {
	t.Helper()

	orig := gatesWarnOut
	t.Cleanup(func() { gatesWarnOut = orig })

	buf := &bytes.Buffer{}
	gatesWarnOut = buf
	return buf
}

// writeTempAgentfile writes a minimal valid Agentfile with the given
// extra YAML (human_gates and/or mcp blocks) and returns its path.
func writeTempAgentfile(t *testing.T, extraYAML string) string {
	t.Helper()

	content := `apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: gates-warning-test
  version: "0.0.1"
capabilities:
  - read_file
` + extraYAML

	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("cannot write temp Agentfile: %v", err)
	}
	return path
}

// gatesManifest builds an in-memory manifest for warnUnenforcedHumanGates
// unit cases.
func gatesManifest(gates manifest.HumanGates, servers []manifest.MCPServer) *manifest.AgentManifest {
	return &manifest.AgentManifest{
		APIVersion: "constle.dev/v1alpha1",
		Kind:       "AgentManifest",
		Identity:   manifest.Identity{Name: "gates-warning-test"},
		HumanGates: gates,
		MCP:        manifest.MCP{Servers: servers},
	}
}

// TestWarnUnenforcedHumanGates covers the narrowed warning: only
// require_approval_for entries that provably match no declared MCP tool are
// reported; enforced entries stay silent.
func TestWarnUnenforcedHumanGates(t *testing.T) {
	emailServer := []manifest.MCPServer{
		{ID: "email", URL: "http://10.0.0.5:9000/mcp", Tools: []string{"send_email"}},
	}

	tests := []struct {
		name           string
		m              *manifest.AgentManifest
		wantWarn       bool
		wantListed     []string
		wantNotListed  []string
		wantNoMCPGloss bool
	}{
		{
			name: "entries without any MCP servers all warn",
			m: gatesManifest(manifest.HumanGates{
				Enabled:            true,
				RequireApprovalFor: []string{"send_email", "payment"},
			}, nil),
			wantWarn:       true,
			wantListed:     []string{"send_email", "payment"},
			wantNoMCPGloss: true,
		},
		{
			name: "entry matching a declared tool stays silent",
			m: gatesManifest(manifest.HumanGates{
				Enabled:            true,
				RequireApprovalFor: []string{"send_email"},
			}, emailServer),
			wantWarn: false,
		},
		{
			name: "only the unmatched entry is listed",
			m: gatesManifest(manifest.HumanGates{
				Enabled:            true,
				RequireApprovalFor: []string{"send_email", "payment"},
			}, emailServer),
			wantWarn:      true,
			wantListed:    []string{"payment"},
			wantNotListed: []string{"send_email,"},
		},
		{
			name: "server without a tools list makes entries possibly enforced — silent",
			m: gatesManifest(manifest.HumanGates{
				Enabled:            true,
				RequireApprovalFor: []string{"anything_at_all"},
			}, []manifest.MCPServer{{ID: "open", URL: "http://10.0.0.5:9000/mcp"}}),
			wantWarn: false,
		},
		{
			name:     "enabled without actions stays silent",
			m:        gatesManifest(manifest.HumanGates{Enabled: true}, nil),
			wantWarn: false,
		},
		{
			name:     "disabled and empty stays silent",
			m:        gatesManifest(manifest.HumanGates{Enabled: false}, nil),
			wantWarn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := withCapturedGatesWarn(t)

			warnUnenforcedHumanGates(tt.m)

			out := buf.String()
			if !tt.wantWarn {
				if out != "" {
					t.Errorf("expected no warning, got:\n%s", out)
				}
				return
			}
			if !strings.Contains(out, "⚠️") {
				t.Errorf("expected a ⚠️ warning, got:\n%s", out)
			}
			if !strings.Contains(out, "NOT enforced") {
				t.Errorf("warning should state entries are NOT enforced, got:\n%s", out)
			}
			for _, action := range tt.wantListed {
				if !strings.Contains(out, action) {
					t.Errorf("warning should list unenforced entry %q, got:\n%s", action, out)
				}
			}
			for _, needle := range tt.wantNotListed {
				if strings.Contains(out, needle) {
					t.Errorf("warning must not list enforced entries (%q), got:\n%s", needle, out)
				}
			}
			if tt.wantNoMCPGloss && !strings.Contains(out, "no mcp.servers are declared") {
				t.Errorf("warning should explain that no MCP servers are declared, got:\n%s", out)
			}
		})
	}
}

// TestValidateWarnsOnUnenforceableGates is the regression guard for the
// `constle validate` path: an Agentfile whose require_approval_for entries
// match no declared MCP tool must produce the not-enforced warning.
func TestValidateWarnsOnUnenforceableGates(t *testing.T) {
	buf := withCapturedGatesWarn(t)
	path := writeTempAgentfile(t, `human_gates:
  enabled: true
  require_approval_for:
    - send_email
  approver_pubkey: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99mXQkL3vUbEr8W3hosJqFr"
`)

	if err := cmdValidate(path); err != nil {
		t.Fatalf("cmdValidate() error = %v, want nil", err)
	}

	out := buf.String()
	if !strings.Contains(out, "NOT enforced") {
		t.Errorf("validate should warn about unenforceable gate entries, got:\n%s", out)
	}
	if !strings.Contains(out, "send_email") {
		t.Errorf("validate warning should list the ungated action, got:\n%s", out)
	}
}

// TestValidateQuietWhenGatesAreEnforced: entries that match a declared MCP
// tool are enforced by the gate proxy, so validate must not warn.
func TestValidateQuietWhenGatesAreEnforced(t *testing.T) {
	buf := withCapturedGatesWarn(t)
	path := writeTempAgentfile(t, `mcp:
  servers:
    - id: email
      url: "http://10.0.0.5:9000/mcp"
      tools: [send_email]
human_gates:
  enabled: true
  require_approval_for:
    - send_email
  approver_pubkey: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99mXQkL3vUbEr8W3hosJqFr"
`)

	if err := cmdValidate(path); err != nil {
		t.Fatalf("cmdValidate() error = %v, want nil", err)
	}

	if out := buf.String(); out != "" {
		t.Errorf("validate must not warn when every gate entry is enforced, got:\n%s", out)
	}
}

// TestValidateQuietWithoutDeclaredHumanGates makes sure the warning is scoped
// to declared gates only — a manifest with human_gates disabled and no
// approval list must stay silent.
func TestValidateQuietWithoutDeclaredHumanGates(t *testing.T) {
	buf := withCapturedGatesWarn(t)
	path := writeTempAgentfile(t, `human_gates:
  enabled: false
`)

	if err := cmdValidate(path); err != nil {
		t.Fatalf("cmdValidate() error = %v, want nil", err)
	}

	if out := buf.String(); out != "" {
		t.Errorf("validate should not warn when no human gates are declared, got:\n%s", out)
	}
}

// TestRunWarnsOnUnenforceableGates is the regression guard for the
// `constle run` path. The bogus --backend override makes cmdRun fail during
// backend detection — after Agentfile loading — so the test proves the
// warning fires on run without needing a real sandbox backend.
func TestRunWarnsOnUnenforceableGates(t *testing.T) {
	buf := withCapturedGatesWarn(t)
	path := writeTempAgentfile(t, `human_gates:
  enabled: true
  require_approval_for:
    - payment
  approver_pubkey: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99mXQkL3vUbEr8W3hosJqFr"
`)

	err := cmdRun(runOptions{agentfile: path, backendOverride: "no-such-backend"})
	if err == nil {
		t.Fatal("cmdRun() error = nil, want an unknown-backend error")
	}
	if !strings.Contains(err.Error(), "unknown backend") {
		t.Fatalf("cmdRun() error = %v, want an unknown-backend error", err)
	}

	out := buf.String()
	if !strings.Contains(out, "NOT enforced") {
		t.Errorf("run should warn about unenforceable gate entries, got:\n%s", out)
	}
}

// captureStdout runs fn with os.Stdout redirected into a pipe and returns what
// was written. printValidatePlain writes through printf to the real stdout, so
// the warn-writer helpers above cannot see it — this is the only way to assert
// on validate's rendered body. Same shape as stop_test.go's capture.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	os.Stdout = orig
	_ = w.Close()
	out, _ := io.ReadAll(r)
	_ = r.Close()
	return string(out)
}

// disabledGatesAgentfile declares a gate that matches a real tool on a real
// server — everything a working gate needs — and then switches the master
// switch off. This is the manifest F17/F24/F77 was about.
const disabledGatesAgentfile = `mcp:
  servers:
    - id: email
      url: "http://10.0.0.5:9000/mcp"
      tools: [send_email]
human_gates:
  enabled: false
  require_approval_for:
    - send_email
  approver_pubkey: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99mXQkL3vUbEr8W3hosJqFr"
`

// TestValidateWarnsWhenGatesAreDeclaredButDisabled: with the master switch
// off, the entry matches a declared tool perfectly and is still not enforced.
// The warning has to name the switch — pointing at the tool mapping instead
// would send an operator hunting for a typo that isn't there.
func TestValidateWarnsWhenGatesAreDeclaredButDisabled(t *testing.T) {
	buf := withCapturedGatesWarn(t)
	path := writeTempAgentfile(t, disabledGatesAgentfile)

	if err := cmdValidate(path); err != nil {
		t.Fatalf("cmdValidate() error = %v, want nil", err)
	}

	out := buf.String()
	if !strings.Contains(out, "human_gates.enabled") {
		t.Errorf("warning must name the master switch, got:\n%s", out)
	}
	if !strings.Contains(out, "send_email") {
		t.Errorf("warning must name the entry that will run ungated, got:\n%s", out)
	}
	if strings.Contains(out, "match no tool") {
		t.Errorf("warning blames the tool mapping for a disabled switch, got:\n%s", out)
	}
}

// TestValidateDoesNotClaimEnforcementWhenGatesAreDisabled is the regression
// guard for the false assurance itself: validate used to print
// "enforced: send_email (paused at the MCP gate proxy for approval)" for a
// manifest the proxy forwards ungated.
func TestValidateDoesNotClaimEnforcementWhenGatesAreDisabled(t *testing.T) {
	withCapturedGatesWarn(t)
	path := writeTempAgentfile(t, disabledGatesAgentfile)

	var cmdErr error
	out := captureStdout(t, func() { cmdErr = cmdValidate(path) })
	if cmdErr != nil {
		t.Fatalf("cmdValidate() error = %v, want nil", cmdErr)
	}

	if strings.Contains(out, "enforced:") {
		t.Errorf("validate claims enforcement while human_gates.enabled is false, got:\n%s", out)
	}
	if strings.Contains(out, "paused at the MCP gate proxy") {
		t.Errorf("validate promises a pause the gate proxy never performs, got:\n%s", out)
	}
}

// TestValidateStillReportsEnforcementWhenGatesAreOn is the other half: the
// honest "enforced" line must survive, or the fix has simply deleted a true
// statement along with the false one.
func TestValidateStillReportsEnforcementWhenGatesAreOn(t *testing.T) {
	withCapturedGatesWarn(t)
	path := writeTempAgentfile(t, strings.Replace(
		disabledGatesAgentfile, "enabled: false", "enabled: true", 1))

	var cmdErr error
	out := captureStdout(t, func() { cmdErr = cmdValidate(path) })
	if cmdErr != nil {
		t.Fatalf("cmdValidate() error = %v, want nil", cmdErr)
	}

	if !strings.Contains(out, "enforced:") || !strings.Contains(out, "send_email") {
		t.Errorf("validate must still report a real gate as enforced, got:\n%s", out)
	}
}

// TestRunWarnsWhenGatesAreDeclaredButDisabled: `constle run` never printed an
// "enforced" line, so its half of the bug was pure silence — the run started
// with no gate and said nothing. Same bogus-backend technique as
// TestRunWarnsOnUnenforceableGates.
func TestRunWarnsWhenGatesAreDeclaredButDisabled(t *testing.T) {
	buf := withCapturedGatesWarn(t)
	path := writeTempAgentfile(t, disabledGatesAgentfile)

	err := cmdRun(runOptions{agentfile: path, backendOverride: "no-such-backend"})
	if err == nil || !strings.Contains(err.Error(), "unknown backend") {
		t.Fatalf("cmdRun() error = %v, want an unknown-backend error", err)
	}

	out := buf.String()
	if !strings.Contains(out, "human_gates.enabled") {
		t.Errorf("run must warn that the master switch disarms the declared gate, got:\n%s", out)
	}
	if !strings.Contains(out, "send_email") {
		t.Errorf("run warning must name the ungated entry, got:\n%s", out)
	}
}

// TestValidateNeverClaimsEnforcementFromCapabilitiesAlone closes the gap an
// independent review found in the first pass of this fix.
//
// The capability list is spec-level advice: declaring send_email there gates no
// call on its own (spec §8). Enforcement comes only from require_approval_for.
// With the master switch on and require_approval_for EMPTY, the proxy arms
// nothing — and validate used to print "approval required by spec — enforced
// for matching MCP tools" anyway. Guarding that row on the master switch was
// not enough, because the switch was on; the row simply must not speak about
// enforcement at all.
func TestValidateNeverClaimsEnforcementFromCapabilitiesAlone(t *testing.T) {
	withCapturedGatesWarn(t)
	// The helper's header already opens a capabilities list; continue it
	// rather than declaring a second one, which is a duplicate key.
	path := writeTempAgentfile(t, `  - send_email
mcp:
  servers:
    - id: email
      url: "http://10.0.0.5:9000/mcp"
      tools: [send_email]
human_gates:
  enabled: true
  require_approval_for: []
`)

	var cmdErr error
	out := captureStdout(t, func() { cmdErr = cmdValidate(path) })
	if cmdErr != nil {
		t.Fatalf("cmdValidate() error = %v, want nil", cmdErr)
	}

	if !strings.Contains(out, "human gates") || !strings.Contains(out, "send_email") {
		t.Fatalf("the spec-level advice row should still appear, got:\n%s", out)
	}
	if strings.Contains(out, "enforced") {
		t.Errorf("nothing is gated — require_approval_for is empty — yet validate says enforced:\n%s", out)
	}
	if strings.Contains(out, "paused at the MCP gate proxy") {
		t.Errorf("validate promises a pause for a call the proxy forwards:\n%s", out)
	}
}
