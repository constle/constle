package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/homedir"
	"github.com/constle/constle/internal/sandbox"
	"github.com/constle/constle/pkg/manifest"
)

// TestParseRunArgs covers the flags that decide how a run is isolated. The
// isolation-relevant cases are the point: --backend picks an engine, and
// --accept-isolation is the only input that can weaken a declared boundary,
// so an unparseable value for it must abort rather than be read as "some
// downgrade was requested".
func TestParseRunArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantErr    string
		wantFile   string
		wantEngine string
		wantAccept manifest.IsolationLevel
	}{
		{
			name:     "agentfile only",
			args:     []string{"agent.yaml"},
			wantFile: "agent.yaml",
		},
		{
			name:       "backend override",
			args:       []string{"--backend=firecracker", "agent.yaml"},
			wantFile:   "agent.yaml",
			wantEngine: "firecracker",
		},
		{
			name:       "accept isolation",
			args:       []string{"--accept-isolation=network", "agent.yaml"},
			wantFile:   "agent.yaml",
			wantAccept: manifest.IsolationNetwork,
		},
		{
			name:       "both flags, flags after the path",
			args:       []string{"agent.yaml", "--backend=docker", "--accept-isolation=process"},
			wantFile:   "agent.yaml",
			wantEngine: "docker",
			wantAccept: manifest.IsolationProcess,
		},
		{
			name:    "unknown isolation level is rejected",
			args:    []string{"--accept-isolation=kernal", "agent.yaml"},
			wantErr: "unknown isolation level",
		},
		{
			name:    "empty isolation level is rejected",
			args:    []string{"--accept-isolation=", "agent.yaml"},
			wantErr: "unknown isolation level",
		},
		{
			name:    "unknown flag",
			args:    []string{"--allow-anything", "agent.yaml"},
			wantErr: "unknown flag",
		},
		{
			name:    "no agentfile",
			args:    []string{"--backend=docker"},
			wantErr: "usage: constle run",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := parseRunArgs(tt.args)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseRunArgs(%q) error = nil, want %q", tt.args, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseRunArgs(%q) error = %v, want nil", tt.args, err)
			}
			if opts.agentfile != tt.wantFile {
				t.Errorf("agentfile = %q, want %q", opts.agentfile, tt.wantFile)
			}
			if opts.backendOverride != tt.wantEngine {
				t.Errorf("backendOverride = %q, want %q", opts.backendOverride, tt.wantEngine)
			}
			if opts.acceptIsolation != tt.wantAccept {
				t.Errorf("acceptIsolation = %q, want %q", opts.acceptIsolation, tt.wantAccept)
			}
		})
	}
}

// TestParseRunArgsDefaultsToNoDowngrade is the important default: absent the
// flag, no downgrade is authorized, so an unsatisfiable contract fails closed
// downstream instead of quietly running weaker.
func TestParseRunArgsDefaultsToNoDowngrade(t *testing.T) {
	opts, err := parseRunArgs([]string{"agent.yaml"})
	if err != nil {
		t.Fatalf("parseRunArgs() error = %v, want nil", err)
	}
	if opts.acceptIsolation != "" {
		t.Errorf("acceptIsolation = %q, want empty — a downgrade must never be the default",
			opts.acceptIsolation)
	}
}

// TestRunStartedDetailsSeparatesRequestedFromAchieved is the evidence half of
// the isolation contract: an audit reader must be able to tell what the
// Agentfile asked for from what the sandbox actually delivered. The entry's
// isolation_level carries the requested minimum (written by the caller);
// these details carry the achieved boundary and, when they differ, the fact
// that an operator accepted the difference.
func TestRunStartedDetailsSeparatesRequestedFromAchieved(t *testing.T) {
	m := &manifest.AgentManifest{}
	m.Sandbox.Isolation = manifest.IsolationKernel
	m.Sandbox.Image = "python:3.11-slim"

	t.Run("satisfied contract", func(t *testing.T) {
		details := runStartedDetails(m, &sandbox.Selection{
			Type:      sandbox.BackendFirecracker,
			Requested: manifest.IsolationKernel,
			Achieved:  manifest.IsolationKernel,
		})

		if got := details["isolation_achieved"]; got != string(manifest.IsolationKernel) {
			t.Errorf("isolation_achieved = %v, want %q", got, manifest.IsolationKernel)
		}
		if _, ok := details["isolation_downgrade_accepted"]; ok {
			t.Error("isolation_downgrade_accepted must be absent when nothing was downgraded")
		}
		if got := details["backend"]; got != string(sandbox.BackendFirecracker) {
			t.Errorf("backend = %v, want %q", got, sandbox.BackendFirecracker)
		}
	})

	t.Run("accepted downgrade", func(t *testing.T) {
		details := runStartedDetails(m, &sandbox.Selection{
			Type:       sandbox.BackendDocker,
			Requested:  manifest.IsolationKernel,
			Achieved:   manifest.IsolationNetwork,
			Downgraded: true,
		})

		if got := details["isolation_achieved"]; got != string(manifest.IsolationNetwork) {
			t.Errorf("isolation_achieved = %v, want %q — a kernel request served by Docker "+
				"must not be recorded as kernel isolation", got, manifest.IsolationNetwork)
		}
		if got := details["isolation_downgrade_accepted"]; got != true {
			t.Errorf("isolation_downgrade_accepted = %v, want true", got)
		}
	})
}

// writeIsolationAgentfile writes a complete Agentfile whose sandbox block
// declares the given isolation level verbatim, so a malformed level reaches
// the real parse/validate path exactly as an operator would have typed it.
func writeIsolationAgentfile(t *testing.T, level string) string {
	t.Helper()

	content := `apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: isolation-contract-test
  version: "0.0.1"
capabilities:
  - external_transfer
sandbox:
  isolation: ` + level + `
  image: "python:3.11-slim"
`
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("cannot write temp Agentfile: %v", err)
	}
	return path
}

// TestRunRejectsMalformedIsolationBeforeBackendSelection is the CLI-path
// regression guard for the blocking hole. An agent declaring external_transfer
// with `isolation: kernal` used to validate, rank as "none", and run on Docker
// with no downgrade recorded and no operator acceptance.
//
// The bogus --backend value is what proves the ORDERING: if the manifest were
// still accepted, cmdRun would reach backend selection and fail with "unknown
// backend" instead. Getting the isolation error back means the run aborted at
// validation — before any backend was chosen, and so before Start.
func TestRunRejectsMalformedIsolationBeforeBackendSelection(t *testing.T) {
	for _, level := range []string{"kernal", "Kernel", `" kernel "`, "hardware"} {
		t.Run(level, func(t *testing.T) {
			path := writeIsolationAgentfile(t, level)

			err := cmdRun(runOptions{agentfile: path, backendOverride: "no-such-backend"})
			if err == nil {
				t.Fatal("cmdRun() error = nil, want a rejection for a malformed isolation level")
			}
			if !strings.Contains(err.Error(), "sandbox.isolation") {
				t.Errorf("error should name sandbox.isolation, got: %v", err)
			}
			if strings.Contains(err.Error(), "unknown backend") {
				t.Errorf("run reached backend selection before rejecting the manifest — "+
					"a malformed isolation level must abort first, got: %v", err)
			}
		})
	}
}

// TestValidateRejectsMalformedIsolationViaCLI covers the same hole through
// `constle validate`, which is where an operator would expect to catch a typo
// before ever attempting a run.
func TestValidateRejectsMalformedIsolationViaCLI(t *testing.T) {
	path := writeIsolationAgentfile(t, "kernal")

	err := cmdValidate(path)
	if err == nil {
		t.Fatal("cmdValidate() error = nil, want a rejection for isolation: kernal")
	}
	if !strings.Contains(err.Error(), "kernal") {
		t.Errorf("error should quote the offending value, got: %v", err)
	}
}

// TestValidateAcceptsWellFormedIsolationViaCLI keeps the rejection from
// having narrowed what a legitimate Agentfile may declare.
func TestValidateAcceptsWellFormedIsolationViaCLI(t *testing.T) {
	for _, level := range []string{"none", "process", "network", "kernel"} {
		if err := cmdValidate(writeIsolationAgentfile(t, level)); err != nil {
			t.Errorf("cmdValidate() rejected the valid level %q: %v", level, err)
		}
	}
}

// TestRunStartedAuditJSONSeparatesRequestedFromAchieved asserts the SERIALIZED
// audit record, not a hand-built details map: the bytes a compliance reader
// actually parses must keep the requested minimum and the delivered boundary
// as distinct fields, and must name an accepted downgrade outright.
func TestRunStartedAuditJSONSeparatesRequestedFromAchieved(t *testing.T) {
	m, err := manifest.Parse([]byte(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: money-mover
capabilities:
  - external_transfer
sandbox:
  isolation: kernel
  image: "python:3.11-slim"
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	tests := []struct {
		name          string
		sel           *sandbox.Selection
		wantAchieved  string
		wantDowngrade bool
	}{
		{
			name: "kernel delivered on firecracker",
			sel: &sandbox.Selection{
				Type:      sandbox.BackendFirecracker,
				Requested: manifest.IsolationKernel,
				Achieved:  manifest.IsolationKernel,
			},
			wantAchieved: "kernel",
		},
		{
			name: "kernel requested, network delivered on docker",
			sel: &sandbox.Selection{
				Type:       sandbox.BackendDocker,
				Requested:  manifest.IsolationKernel,
				Achieved:   manifest.IsolationNetwork,
				Downgraded: true,
			},
			wantAchieved:  "network",
			wantDowngrade: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logLoc := homedir.Under(t.TempDir(), "audit.jsonl")
			logPath := logLoc.String()
			logger, err := audit.New(logLoc)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() { _ = logger.Close() }()

			if err := logger.LogWithIsolation(
				"run-1", m.Identity.Name, audit.EventRunStarted,
				string(m.Sandbox.Isolation), runStartedDetails(m, tt.sel),
			); err != nil {
				t.Fatalf("LogWithIsolation() error = %v", err)
			}

			raw, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("cannot read audit log: %v", err)
			}

			var entry struct {
				Event          string         `json:"event"`
				IsolationLevel string         `json:"isolation_level"`
				Details        map[string]any `json:"details"`
			}
			line := strings.TrimSpace(string(raw))
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatalf("audit line is not valid JSON: %v\nline: %s", err, line)
			}

			if entry.Event != string(audit.EventRunStarted) {
				t.Errorf("event = %q, want %q", entry.Event, audit.EventRunStarted)
			}
			// The requested minimum: always what the Agentfile declared.
			if entry.IsolationLevel != "kernel" {
				t.Errorf("isolation_level = %q, want \"kernel\" (the requested minimum)",
					entry.IsolationLevel)
			}
			// The delivered boundary: never overstated as the requested one.
			if got := entry.Details["isolation_achieved"]; got != tt.wantAchieved {
				t.Errorf("details.isolation_achieved = %v, want %q", got, tt.wantAchieved)
			}

			_, present := entry.Details["isolation_downgrade_accepted"]
			if present != tt.wantDowngrade {
				t.Errorf("details.isolation_downgrade_accepted present = %v, want %v",
					present, tt.wantDowngrade)
			}
			if tt.wantDowngrade && entry.Details["isolation_downgrade_accepted"] != true {
				t.Errorf("details.isolation_downgrade_accepted = %v, want true",
					entry.Details["isolation_downgrade_accepted"])
			}

			// The two must never be the same field read twice.
			if tt.wantDowngrade && entry.IsolationLevel == tt.wantAchieved {
				t.Error("requested and achieved isolation collapsed to one value on a downgraded run")
			}
		})
	}
}
