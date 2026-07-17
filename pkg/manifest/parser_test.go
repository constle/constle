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

func TestParseMCPAndGateDefaults(t *testing.T) {
	yaml := `
apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: test-agent
mcp:
  servers:
    - id: email
      url: "http://10.1.2.3:9000/mcp"
      tools: [send_email, list_inbox]
human_gates:
  enabled: true
  require_approval_for: [send_email]
  notify:
    - channel: webhook
      url_secret_ref: HUMAN_GATE_WEBHOOK_URL
`

	m, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(m.MCP.Servers) != 1 || m.MCP.Servers[0].ID != "email" {
		t.Fatalf("mcp.servers not parsed: %+v", m.MCP.Servers)
	}
	if got := m.MCP.Servers[0].Tools; len(got) != 2 || got[0] != "send_email" {
		t.Errorf("tools = %v, want [send_email list_inbox]", got)
	}
	if m.HumanGates.ApprovalTimeoutSeconds != 300 {
		t.Errorf("approval_timeout_seconds default = %d, want 300", m.HumanGates.ApprovalTimeoutSeconds)
	}
	if len(m.HumanGates.Notify) != 1 || m.HumanGates.Notify[0].URLSecretRef != "HUMAN_GATE_WEBHOOK_URL" {
		t.Errorf("notify not parsed: %+v", m.HumanGates.Notify)
	}

	if err := m.Validate(); err != nil {
		t.Errorf("valid MCP manifest failed validation: %v", err)
	}
}

// validManifestWithMCP builds a minimal valid manifest with one MCP server,
// for validation tests to mutate.
func validManifestWithMCP() *AgentManifest {
	return &AgentManifest{
		APIVersion: "constle.dev/v1alpha1",
		Kind:       "AgentManifest",
		Identity:   Identity{Name: "my-agent"},
		MCP: MCP{Servers: []MCPServer{
			{ID: "email", URL: "http://10.1.2.3:9000/mcp", Tools: []string{"send_email"}},
		}},
	}
}

func TestValidateMCP(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*AgentManifest)
		wantErr bool
	}{
		{
			name:    "valid server",
			mutate:  func(m *AgentManifest) {},
			wantErr: false,
		},
		{
			name: "missing id",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].ID = ""
			},
			wantErr: true,
		},
		{
			name: "invalid id charset",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].ID = "Email Server!"
			},
			wantErr: true,
		},
		{
			name: "duplicate id",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers = append(m.MCP.Servers, m.MCP.Servers[0])
			},
			wantErr: true,
		},
		{
			name: "missing url",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = ""
			},
			wantErr: true,
		},
		{
			name: "non-http url",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "stdio:///usr/bin/mcp-email"
			},
			wantErr: true,
		},
		{
			name: "MCP host also in allowed_hosts — gate bypass",
			mutate: func(m *AgentManifest) {
				m.Sandbox.Network.AllowedHosts = []string{"10.1.2.3"}
			},
			wantErr: true,
		},
		{
			name: "subdomain wildcard covering MCP host — gate bypass",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://mcp.example.com/mcp"
				m.Sandbox.Network.AllowedHosts = []string{".example.com"}
			},
			wantErr: true,
		},
		{
			name: "loopback alias in allowed_hosts with MCP declared — gate bypass",
			mutate: func(m *AgentManifest) {
				m.Sandbox.Network.AllowedHosts = []string{"host.docker.internal"}
			},
			wantErr: true,
		},
		{
			name: "loopback alias allowed when no MCP servers declared",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers = nil
				m.Sandbox.Network.AllowedHosts = []string{"host.docker.internal"}
			},
			wantErr: false,
		},
		{
			name: "unrelated allowed_hosts are fine",
			mutate: func(m *AgentManifest) {
				m.Sandbox.Network.AllowedHosts = []string{"api.openai.com"}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifestWithMCP()
			tt.mutate(m)
			err := m.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidateHumanGates(t *testing.T) {
	m := validManifestWithMCP()
	m.HumanGates.Notify = []NotifyChannel{{Channel: "email", URLSecretRef: "X"}}
	if err := m.Validate(); err == nil {
		t.Error("expected error for unsupported notify channel, got nil")
	}

	m = validManifestWithMCP()
	m.HumanGates.Notify = []NotifyChannel{{Channel: "webhook"}}
	if err := m.Validate(); err == nil {
		t.Error("expected error for webhook without url_secret_ref, got nil")
	}

	m = validManifestWithMCP()
	m.HumanGates.OnTimeout = "retry"
	if err := m.Validate(); err == nil {
		t.Error("expected error for unsupported on_timeout, got nil")
	}

	m = validManifestWithMCP()
	m.HumanGates.ApprovalTimeoutSeconds = -5
	if err := m.Validate(); err == nil {
		t.Error("expected error for negative approval_timeout_seconds, got nil")
	}
}

func TestEnforcedGateEntries(t *testing.T) {
	m := validManifestWithMCP()
	m.HumanGates.RequireApprovalFor = []string{"send_email", "payment"}

	enforced, unenforced := m.EnforcedGateEntries()
	if len(enforced) != 1 || enforced[0] != "send_email" {
		t.Errorf("enforced = %v, want [send_email]", enforced)
	}
	if len(unenforced) != 1 || unenforced[0] != "payment" {
		t.Errorf("unenforced = %v, want [payment]", unenforced)
	}

	// A server without a tools allowlist makes every entry possibly enforced.
	m.MCP.Servers[0].Tools = nil
	enforced, unenforced = m.EnforcedGateEntries()
	if len(enforced) != 2 || len(unenforced) != 0 {
		t.Errorf("with open tool list: enforced = %v, unenforced = %v, want all enforced", enforced, unenforced)
	}

	// No MCP servers at all: nothing is enforced.
	m.MCP.Servers = nil
	enforced, unenforced = m.EnforcedGateEntries()
	if len(enforced) != 0 || len(unenforced) != 2 {
		t.Errorf("with no servers: enforced = %v, unenforced = %v, want all unenforced", enforced, unenforced)
	}
}
