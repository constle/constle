package manifest

import (
	"strings"
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

// TestIsolationLevelSatisfies pins the ordering the isolation contract is
// decided on: the runtime refuses a run whenever the boundary it can build
// does not Satisfy the level the Agentfile declared.
func TestIsolationLevelSatisfies(t *testing.T) {
	ordered := []IsolationLevel{IsolationNone, IsolationProcess, IsolationNetwork, IsolationKernel}

	for i, have := range ordered {
		for j, required := range ordered {
			want := i >= j
			if got := have.Satisfies(required); got != want {
				t.Errorf("%q.Satisfies(%q) = %v, want %v", have, required, got, want)
			}
		}
	}
}

// TestSatisfiesFailsClosedOnInvalidOperands is the defense-in-depth half of
// the contract. An unrecognized level ranks as nothing, so without this guard
// `kernal` would rank BELOW every real level and be "satisfied" by the
// weakest backend on the host — a typo turning a kernel requirement into no
// requirement at all. Neither operand position may be satisfiable.
func TestSatisfiesFailsClosedOnInvalidOperands(t *testing.T) {
	invalid := []IsolationLevel{"", "kernal", "Kernel", " kernel ", "hardware"}
	valid := []IsolationLevel{IsolationNone, IsolationProcess, IsolationNetwork, IsolationKernel}

	for _, bad := range invalid {
		for _, good := range valid {
			// A malformed REQUIREMENT must never read as satisfied, however
			// strong the boundary on offer.
			if good.Satisfies(bad) {
				t.Errorf("%q.Satisfies(%q) = true, want false — a malformed requirement "+
					"must never be satisfiable", good, bad)
			}
			// A malformed PROVIDED level must never satisfy a real one.
			if bad.Satisfies(good) {
				t.Errorf("%q.Satisfies(%q) = true, want false — a malformed boundary "+
					"must never satisfy a real requirement", bad, good)
			}
		}
		if bad.Satisfies(bad) {
			t.Errorf("%q.Satisfies(itself) = true, want false", bad)
		}
	}
}

// TestValidateRejectsMalformedIsolation is the regression guard for the
// blocking hole: `isolation: kernal` used to validate cleanly, keep its
// unknown string through parsing, rank as "none", and let an agent declaring
// external_transfer run on Docker with no downgrade and no acceptance. It
// must now be a rejected Agentfile.
func TestValidateRejectsMalformedIsolation(t *testing.T) {
	for _, level := range []string{
		"kernal",     // the transposition that started this
		"Kernel",     // case variant
		"KERNEL",     // case variant
		`" kernel "`, // whitespace variant (quoted so YAML preserves it)
		`"kernel "`,
		`" "`,
		"hardware", // plausible-sounding but undefined
		"vm",
		"full",
	} {
		t.Run(level, func(t *testing.T) {
			m, err := Parse([]byte(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: typo-agent
capabilities:
  - external_transfer
sandbox:
  isolation: ` + level + `
`))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil (the value is well-formed YAML)", err)
			}

			// The parser must preserve what was authored rather than repair
			// it — guessing which level was meant is how a weaker boundary
			// gets silently substituted for a declared one.
			if m.Sandbox.IsolationInferred {
				t.Error("an explicitly written level must not be marked inferred")
			}

			err = m.Validate()
			if err == nil {
				t.Fatalf("Validate() error = nil for isolation %s — a malformed level must fail closed", level)
			}
			if !strings.Contains(err.Error(), "sandbox.isolation") {
				t.Errorf("error should name the offending field, got: %v", err)
			}
		})
	}
}

// TestValidateAcceptsEveryDefinedLevel is the other side of that guard: the
// rejection must not have narrowed what a legitimate Agentfile may declare.
func TestValidateAcceptsEveryDefinedLevel(t *testing.T) {
	for _, level := range []string{"none", "process", "network", "kernel"} {
		m, err := Parse([]byte(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: ok-agent
sandbox:
  isolation: ` + level + `
`))
		if err != nil {
			t.Fatalf("Parse(%q) error = %v", level, err)
		}
		if err := m.Validate(); err != nil {
			t.Errorf("Validate() rejected the valid level %q: %v", level, err)
		}
		if m.Sandbox.IsolationInferred {
			t.Errorf("isolation %q was declared, not inferred", level)
		}
	}
}

// TestIsolationInferredFlag pins the distinction the validate output depends
// on: a level Constle derived vs. one the operator wrote. Reporting a
// declared level as "inferred" credits the runtime with a choice it did not
// make — and previously described a typo'd level that way too.
func TestIsolationInferredFlag(t *testing.T) {
	inferred, err := Parse([]byte(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: infer-agent
capabilities:
  - external_transfer
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !inferred.Sandbox.IsolationInferred {
		t.Error("IsolationInferred = false, want true when no level is written")
	}
	if inferred.Sandbox.Isolation != IsolationKernel {
		t.Errorf("inferred level = %q, want %q", inferred.Sandbox.Isolation, IsolationKernel)
	}
}

// TestParseIsolationLevel keeps an unrecognized level out of the one input
// that can weaken a declared boundary — a typo must be an error, never a
// level that silently ranks as "none".
func TestParseIsolationLevel(t *testing.T) {
	for _, valid := range []string{"none", "process", "network", "kernel"} {
		got, err := ParseIsolationLevel(valid)
		if err != nil {
			t.Errorf("ParseIsolationLevel(%q) error = %v, want nil", valid, err)
		}
		if string(got) != valid {
			t.Errorf("ParseIsolationLevel(%q) = %q, want %q", valid, got, valid)
		}
	}

	for _, invalid := range []string{"", "kernal", "Kernel", "hardware", "vm"} {
		if _, err := ParseIsolationLevel(invalid); err == nil {
			t.Errorf("ParseIsolationLevel(%q) error = nil, want a rejection", invalid)
		}
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

// identity.name is used unmodified as a path element — the identity
// directory and the audit log filename — so a name carrying path separators
// or dot-segments relocates that state outside ~/.constle, where constle
// then creates and (under sudo) chowns it. The check must hold for every
// manifest, not only the signed ones: identity.did is optional, and the
// identity-loading path is the only other place the name is validated.
func TestValidateIdentityNameRejectsPathTraversal(t *testing.T) {
	base := func(name string) *AgentManifest {
		return &AgentManifest{
			APIVersion: "constle.dev/v1alpha1",
			Kind:       "AgentManifest",
			Identity:   Identity{Name: name},
		}
	}

	for _, bad := range []string{
		"../../../etc/passwd",
		"../../../../etc/constle",
		"nested/agent",
		`..\windows\system32`,
		"..",
		".",
		".hidden",
	} {
		err := base(bad).Validate()
		if err == nil {
			t.Errorf("identity.name %q passed validation, want an error", bad)
			continue
		}
		if !strings.Contains(err.Error(), "identity.name") {
			t.Errorf("identity.name %q: error %q does not name the offending field", bad, err)
		}
	}

	// Ordinary names still pass, with no identity.did declared.
	for _, good := range []string{"my-agent", "agent.v2", "Agent_1"} {
		if err := base(good).Validate(); err != nil {
			t.Errorf("identity.name %q failed validation: %v", good, err)
		}
	}
}

func TestValidateIdentityDID(t *testing.T) {
	base := func(did string) *AgentManifest {
		return &AgentManifest{
			APIVersion: "constle.dev/v1alpha1",
			Kind:       "AgentManifest",
			Identity:   Identity{Name: "my-agent", DID: did},
		}
	}

	// A well-formed did:key (Ed25519) passes.
	good := base("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99mXQkL3vUbEr8W3hosJqFr")
	if err := good.Validate(); err != nil {
		t.Errorf("valid identity.did failed validation: %v", err)
	}

	// Empty DID stays optional — unchanged behavior.
	if err := base("").Validate(); err != nil {
		t.Errorf("manifest without identity.did failed validation: %v", err)
	}

	for _, bad := range []string{
		"did:web:example.com", // wrong method — only did:key is supported
		"did:key:uABCD",       // wrong multibase encoding
		"did:key:z6MkiTBz",    // truncated key
		"not-a-did",
	} {
		if err := base(bad).Validate(); err == nil {
			t.Errorf("identity.did %q passed validation, want error", bad)
		}
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
  approver_pubkey: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99mXQkL3vUbEr8W3hosJqFr"
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

func TestValidateApproverPubkey(t *testing.T) {
	validDID := "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99mXQkL3vUbEr8W3hosJqFr"

	m := validManifestWithMCP()
	m.HumanGates.RequireApprovalFor = []string{"send_email"}
	if err := m.Validate(); err == nil {
		t.Error("expected error for require_approval_for without approver_pubkey, got nil")
	}

	m = validManifestWithMCP()
	m.HumanGates.RequireApprovalFor = []string{"send_email"}
	m.HumanGates.ApproverPubkey = "not-a-did-at-all"
	if err := m.Validate(); err == nil {
		t.Error("expected error for malformed approver_pubkey, got nil")
	}

	m = validManifestWithMCP()
	m.HumanGates.RequireApprovalFor = []string{"send_email"}
	m.HumanGates.ApproverPubkey = "did:web:example.com"
	if err := m.Validate(); err == nil {
		t.Error("expected error for a non-did:key approver_pubkey, got nil")
	}

	m = validManifestWithMCP()
	m.HumanGates.RequireApprovalFor = []string{"send_email"}
	m.HumanGates.ApproverPubkey = validDID
	if err := m.Validate(); err != nil {
		t.Errorf("expected no error for a valid approver_pubkey, got %v", err)
	}

	// approver_pubkey is optional when no gate is declared at all.
	m = validManifestWithMCP()
	if err := m.Validate(); err != nil {
		t.Errorf("expected no error when require_approval_for is empty, got %v", err)
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
