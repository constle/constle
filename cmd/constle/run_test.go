package main

import (
	"strings"
	"testing"

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
