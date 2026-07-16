package main

import (
	"bytes"
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
// human_gates block and returns its path.
func writeTempAgentfile(t *testing.T, humanGatesYAML string) string {
	t.Helper()

	content := `apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: gates-warning-test
  version: "0.0.1"
capabilities:
  - read_file
` + humanGatesYAML

	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("cannot write temp Agentfile: %v", err)
	}
	return path
}

// TestWarnUnenforcedHumanGates covers the trigger condition: any declared
// human gate (enabled, or a non-empty require_approval_for) must warn that
// enforcement does not exist, and an undeclared one must stay silent.
func TestWarnUnenforcedHumanGates(t *testing.T) {
	tests := []struct {
		name     string
		gates    manifest.HumanGates
		wantWarn bool
	}{
		{
			name:     "enabled without actions warns",
			gates:    manifest.HumanGates{Enabled: true},
			wantWarn: true,
		},
		{
			name: "require_approval_for without enabled warns",
			gates: manifest.HumanGates{
				RequireApprovalFor: []string{"send_email"},
			},
			wantWarn: true,
		},
		{
			name: "enabled with actions warns",
			gates: manifest.HumanGates{
				Enabled:            true,
				RequireApprovalFor: []string{"external_transfer", "delete_records"},
			},
			wantWarn: true,
		},
		{
			name:     "disabled and empty stays silent",
			gates:    manifest.HumanGates{Enabled: false},
			wantWarn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := withCapturedGatesWarn(t)

			warnUnenforcedHumanGates(tt.gates)

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
				t.Errorf("warning should state gates are NOT enforced, got:\n%s", out)
			}
			for _, action := range tt.gates.RequireApprovalFor {
				if !strings.Contains(out, action) {
					t.Errorf("warning should list unprotected action %q, got:\n%s", action, out)
				}
			}
		})
	}
}

// TestValidateWarnsOnDeclaredHumanGates is the regression guard for the
// `constle validate` path: an Agentfile that declares human gates must
// produce the not-enforced warning, because the runtime has no
// gate-enforcement engine yet.
func TestValidateWarnsOnDeclaredHumanGates(t *testing.T) {
	buf := withCapturedGatesWarn(t)
	path := writeTempAgentfile(t, `human_gates:
  enabled: true
  require_approval_for:
    - send_email
`)

	if err := cmdValidate(path); err != nil {
		t.Fatalf("cmdValidate() error = %v, want nil", err)
	}

	out := buf.String()
	if !strings.Contains(out, "NOT enforced") {
		t.Errorf("validate should warn that human_gates are NOT enforced, got:\n%s", out)
	}
	if !strings.Contains(out, "send_email") {
		t.Errorf("validate warning should list the ungated action, got:\n%s", out)
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

// TestRunWarnsOnDeclaredHumanGates is the regression guard for the
// `constle run` path. The bogus --backend override makes cmdRun fail during
// backend detection — after Agentfile loading — so the test proves the
// warning fires on run without needing a real sandbox backend.
func TestRunWarnsOnDeclaredHumanGates(t *testing.T) {
	buf := withCapturedGatesWarn(t)
	path := writeTempAgentfile(t, `human_gates:
  enabled: true
`)

	err := cmdRun(path, "no-such-backend")
	if err == nil {
		t.Fatal("cmdRun() error = nil, want an unknown-backend error")
	}
	if !strings.Contains(err.Error(), "unknown backend") {
		t.Fatalf("cmdRun() error = %v, want an unknown-backend error", err)
	}

	out := buf.String()
	if !strings.Contains(out, "NOT enforced") {
		t.Errorf("run should warn that human_gates are NOT enforced, got:\n%s", out)
	}
}
