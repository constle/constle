package manifest

import (
	"testing"
)

func TestInferIsolation(t *testing.T) {
	tests := []struct {
		name     string
		caps     []Capability
		expected IsolationLevel
	}{
		{
			name:     "no capabilities",
			caps:     []Capability{},
			expected: IsolationNone,
		},
		{
			name:     "file read only",
			caps:     []Capability{CapReadFile},
			expected: IsolationProcess,
		},
		{
			name:     "web search",
			caps:     []Capability{CapWebSearch},
			expected: IsolationNetwork,
		},
		{
			name:     "web search + file write — network wins",
			caps:     []Capability{CapWebSearch, CapWriteFile},
			expected: IsolationNetwork,
		},
		{
			name:     "external transfer — requires kernel",
			caps:     []Capability{CapWebSearch, CapExternalTransfer},
			expected: IsolationKernel,
		},
		{
			name:     "delete records",
			caps:     []Capability{CapDeleteRecords},
			expected: IsolationKernel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InferIsolation(tt.caps)
			if got != tt.expected {
				t.Errorf("InferIsolation(%v) = %q, want %q", tt.caps, got, tt.expected)
			}
		})
	}
}

func TestParse(t *testing.T) {
	yaml := `
apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: test-agent
  version: "1.0.0"
sandbox:
  memory_mb: 256
  network:
    egress: restricted
    allowed_hosts:
      - api.openai.com
capabilities:
  - web_search
  - file_write
human_gates:
  enabled: true
  require_approval_for:
    - send_email
`

	m, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if m.Identity.Name != "test-agent" {
		t.Errorf("name = %q, want %q", m.Identity.Name, "test-agent")
	}

	// web_search triggers network isolation.
	if m.Sandbox.Isolation != IsolationNetwork {
		t.Errorf("isolation = %q, want %q", m.Sandbox.Isolation, IsolationNetwork)
	}

	if m.Sandbox.MemoryMB != 256 {
		t.Errorf("memory_mb = %d, want 256", m.Sandbox.MemoryMB)
	}

	if m.HumanGates.OnTimeout != "abort" {
		t.Errorf("on_timeout = %q, want \"abort\"", m.HumanGates.OnTimeout)
	}
}

func TestValidate(t *testing.T) {
	valid := &AgentManifest{
		APIVersion: "constle.dev/v1alpha1",
		Kind:       "AgentManifest",
		Identity:   Identity{Name: "my-agent"},
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("valid manifest failed validation: %v", err)
	}

	bad := &AgentManifest{
		APIVersion: "wrong",
		Kind:       "AgentManifest",
		Identity:   Identity{Name: "my-agent"},
	}
	if err := bad.Validate(); err == nil {
		t.Error("expected error for wrong apiVersion, got nil")
	}

	noName := &AgentManifest{
		APIVersion: "constle.dev/v1alpha1",
		Kind:       "AgentManifest",
	}
	if err := noName.Validate(); err == nil {
		t.Error("expected error for missing name, got nil")
	}
}
