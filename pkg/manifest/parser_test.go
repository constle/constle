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

// sandbox.image is the first positional argument of the Docker backend's
// `docker run`, so a value spelled like an option — "-v", "--privileged" —
// was parsed as one, with sandbox.command supplying its operands and the
// real image: the host filesystem ended up mounted inside the sandbox. The
// backend now ends option parsing with "--" before the image; this check is
// the early refusal that names the field.
func TestValidateSandboxImageRejectsOptionLikeValues(t *testing.T) {
	base := func(image string) *AgentManifest {
		return &AgentManifest{
			APIVersion: "constle.dev/v1alpha1",
			Kind:       "AgentManifest",
			Identity:   Identity{Name: "argv-test"},
			Sandbox:    Sandbox{Image: image},
		}
	}

	for _, bad := range []string{"-v", "--privileged", "--network=host", "--", "-"} {
		err := base(bad).Validate()
		if err == nil {
			t.Errorf("sandbox.image %q passed validation, want an error", bad)
			continue
		}
		if !strings.Contains(err.Error(), "sandbox.image") {
			t.Errorf("sandbox.image %q: error %q does not name the offending field", bad, err)
		}
	}

	// Real references, and the empty pre-choice state, still pass.
	for _, good := range []string{
		"",
		"alpine:latest",
		"python:3.11-slim",
		"ghcr.io/myorg/agent:v1.2.0",
		"localhost:5000/agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	} {
		if err := base(good).Validate(); err != nil {
			t.Errorf("sandbox.image %q failed validation: %v", good, err)
		}
	}

	// sandbox.command is not subject to the check: its elements follow the
	// image, past the point where docker run reads options, and they start
	// with "-" legitimately when the image has an ENTRYPOINT.
	withCmd := base("python:3.11-slim")
	withCmd.Sandbox.Command = []string{"-c", "print('ok')"}
	if err := withCmd.Validate(); err != nil {
		t.Errorf("sandbox.command with a dash-prefixed element failed validation: %v", err)
	}

	// The same rejection must reach a manifest that arrives as YAML — the
	// shape an attacker actually controls — since Parse does not validate.
	doc := []byte(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: argv-test
sandbox:
  image: "-v"
  command: ["/:/host", "alpine:latest", "sh"]
`)
	parsed, err := Parse(doc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := parsed.Validate(); err == nil || !strings.Contains(err.Error(), "sandbox.image") {
		t.Errorf("parsed Agentfile with image \"-v\" validated as %v, want a sandbox.image error", err)
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
		// wantErrContains, when set, requires the refusal to be the one the
		// case is about. Without it a case that starts failing earlier, for
		// an unrelated reason, still passes and stops testing anything.
		wantErrContains string
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
		// The bypass check compares an allowlist entry, which the grammar has
		// already forced to one spelling, against a host taken from a URL,
		// where several spellings of the same name are legal. Every one of
		// these reaches the same server through Squid, which matches names
		// case-insensitively, so every one of them has to be an overlap here.
		{
			name: "MCP host in allowed_hosts, declared in uppercase — gate bypass",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://API.EXAMPLE.COM/mcp"
				m.Sandbox.Network.AllowedHosts = []string{"api.example.com"}
			},
			wantErr:         true,
			wantErrContains: "also appears in network.allowed_hosts",
		},
		{
			name: "MCP host in allowed_hosts, declared in mixed case — gate bypass",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://Api.Example.Com/mcp"
				m.Sandbox.Network.AllowedHosts = []string{"api.example.com"}
			},
			wantErr:         true,
			wantErrContains: "also appears in network.allowed_hosts",
		},
		{
			name: "MCP host in allowed_hosts, declared fully qualified — gate bypass",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://api.example.com./mcp"
				m.Sandbox.Network.AllowedHosts = []string{"api.example.com"}
			},
			wantErr:         true,
			wantErrContains: "also appears in network.allowed_hosts",
		},
		{
			name: "MCP host in allowed_hosts, both spellings at once — gate bypass",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://ApI.eXaMpLe.CoM./mcp"
				m.Sandbox.Network.AllowedHosts = []string{"api.example.com"}
			},
			wantErr:         true,
			wantErrContains: "also appears in network.allowed_hosts",
		},
		{
			name: "subdomain wildcard covering an uppercase MCP host — gate bypass",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://MCP.EXAMPLE.COM/mcp"
				m.Sandbox.Network.AllowedHosts = []string{".example.com"}
			},
			wantErr:         true,
			wantErrContains: "also appears in network.allowed_hosts",
		},
		// Go's HTTP transport runs a URL host through IDNA before resolving
		// it, so each of these is dialled as "api.example.com" while the
		// allowlist grammar can spell none of them. The comparison cannot be
		// made in two alphabets, so a non-ASCII host is refused outright and
		// the operator is pointed at the punycode form.
		{
			name: "MCP host written with an ideographic full stop — uncomparable",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://api\u3002example.com/mcp" // ideographic full stop
				m.Sandbox.Network.AllowedHosts = []string{"api.example.com"}
			},
			wantErr: true,
			// The refusal names the host this manifest would really have
			// dialled, which is the allowlisted one.
			wantErrContains: "resolves to, api.example.com",
		},
		{
			name: "MCP host written with a fullwidth full stop — uncomparable",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://api\uff0eexample.com/mcp" // fullwidth full stop
				m.Sandbox.Network.AllowedHosts = []string{"api.example.com"}
			},
			wantErr:         true,
			wantErrContains: "non-ASCII host",
		},
		{
			name: "MCP host written with fullwidth letters — uncomparable",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://\uff41pi.example.com/mcp" // fullwidth a
				m.Sandbox.Network.AllowedHosts = []string{"api.example.com"}
			},
			wantErr:         true,
			wantErrContains: "non-ASCII host",
		},
		{
			name: "MCP host written with a Cyrillic homoglyph — uncomparable",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://\u0430pi.example.com/mcp" // Cyrillic a
				m.Sandbox.Network.AllowedHosts = []string{"api.example.com"}
			},
			wantErr: true,
			// And here it names a host that is visibly not the one the
			// operator meant, which is the whole value of naming it.
			wantErrContains: "resolves to, xn--pi-6kc.example.com",
		},
		{
			name: "an internationalised MCP host in unicode is refused, with its ASCII form named",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://bücher.example/mcp"
				m.Sandbox.Network.AllowedHosts = []string{"api.openai.com"}
			},
			wantErr:         true,
			wantErrContains: "resolves to, xn--bcher-kva.example",
		},
		{
			// The hint is computed on the normalised host, so the two
			// spellings this commit already folds do not cost the operator
			// the one piece of information the message exists to give.
			name: "an internationalised MCP host, fully qualified and uppercase, still names its form",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://B\u00dcCHER.EXAMPLE./mcp"
				m.Sandbox.Network.AllowedHosts = []string{"api.openai.com"}
			},
			wantErr:         true,
			wantErrContains: "resolves to, xn--bcher-kva.example",
		},
		{
			name: "a non-ASCII host that maps to no usable name names none",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://\u200b.example/mcp" // zero-width space
				m.Sandbox.Network.AllowedHosts = []string{"api.openai.com"}
			},
			wantErr:         true,
			wantErrContains: "is not a usable name",
		},
		{
			name: "an internationalised MCP host in punycode is comparable, and overlaps",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://xn--bcher-kva.example/mcp"
				m.Sandbox.Network.AllowedHosts = []string{"xn--bcher-kva.example"}
			},
			wantErr:         true,
			wantErrContains: "also appears in network.allowed_hosts",
		},
		{
			name: "an internationalised MCP host in punycode, not allowlisted, is fine",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://xn--bcher-kva.example/mcp"
				m.Sandbox.Network.AllowedHosts = []string{"api.openai.com"}
			},
			wantErr: false,
		},
		{
			name: "a different host in another case is still a different host",
			mutate: func(m *AgentManifest) {
				m.MCP.Servers[0].URL = "https://API.EXAMPLE.COM/mcp"
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
			if tt.wantErrContains != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrContains)) {
				t.Errorf("error = %v, want one containing %q", err, tt.wantErrContains)
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
	// The master switch is load-bearing here and is set deliberately: without
	// it nothing is enforced whatever the tool mapping says, which is what
	// TestEnforcedGateEntriesRespectsMasterSwitch covers.
	m.HumanGates.Enabled = true
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

// TestEnforcedGateEntriesRespectsMasterSwitch pins the precedence between the
// master switch and the tool mapping. human_gates.enabled: false disarms the
// gate proxy outright (spec/agent-manifest.md §14.1), so an entry that matches
// a declared tool perfectly is still not enforced — reporting it as enforced
// is what made `constle validate` promise a pause the proxy never performed.
func TestEnforcedGateEntriesRespectsMasterSwitch(t *testing.T) {
	m := validManifestWithMCP()
	m.HumanGates.Enabled = false
	m.HumanGates.RequireApprovalFor = []string{"send_email"}

	enforced, unenforced := m.EnforcedGateEntries()
	if len(enforced) != 0 {
		t.Errorf("enforced = %v, want none: the master switch is off", enforced)
	}
	if len(unenforced) != 1 || unenforced[0] != "send_email" {
		t.Errorf("unenforced = %v, want [send_email]", unenforced)
	}

	// A server with no tools allowlist does not resurrect the entry either:
	// "may match at runtime" is only true while the proxy is arming gates.
	m.MCP.Servers[0].Tools = nil
	if enforced, _ := m.EnforcedGateEntries(); len(enforced) != 0 {
		t.Errorf("with an open tool list: enforced = %v, want none", enforced)
	}

	// Flipping the switch on, and nothing else, enforces it.
	m.MCP.Servers[0].Tools = []string{"send_email"}
	m.HumanGates.Enabled = true
	enforced, unenforced = m.EnforcedGateEntries()
	if len(enforced) != 1 || enforced[0] != "send_email" {
		t.Errorf("with the switch on: enforced = %v, want [send_email]", enforced)
	}
	if len(unenforced) != 0 {
		t.Errorf("with the switch on: unenforced = %v, want none", unenforced)
	}

	// An empty list reports nothing either way — there is no gate to report.
	m.HumanGates.Enabled = false
	m.HumanGates.RequireApprovalFor = nil
	if enforced, unenforced := m.EnforcedGateEntries(); len(enforced) != 0 || len(unenforced) != 0 {
		t.Errorf("with no entries: enforced = %v, unenforced = %v, want both empty", enforced, unenforced)
	}
}

// ------------------------------------------------------------
// The capability floor: a declared level may only strengthen
// ------------------------------------------------------------

// floorAgentfile builds a well-formed Agentfile declaring the given
// capabilities and isolation level, so a below-floor combination reaches the
// real parse/validate path exactly as an operator would have typed it.
func floorAgentfile(level string, caps ...Capability) []byte {
	y := "apiVersion: constle.dev/v1alpha1\nkind: AgentManifest\nidentity:\n  name: floor-agent\n"
	if len(caps) > 0 {
		y += "capabilities:\n"
		for _, cap := range caps {
			y += "  - " + string(cap) + "\n"
		}
	}
	return []byte(y + "sandbox:\n  isolation: " + level + "\n")
}

// TestValidateRejectsIsolationBelowCapabilityFloor is the regression guard for
// the blocking hole: the capability-derived minimum was computed only when
// sandbox.isolation was ABSENT, so writing a weaker level by hand skipped it
// entirely. An Agentfile declaring external_transfer — which demands kernel —
// beside `isolation: network` validated cleanly, handed "network" to backend
// selection, was satisfied outright by Docker, and ran a money mover on a
// shared host kernel with no downgrade recorded and no operator acceptance
// anywhere. Writing the line made the boundary weaker than omitting it would
// have.
func TestValidateRejectsIsolationBelowCapabilityFloor(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		caps     []Capability
		wantFrag []string
	}{
		{
			name:     "the original hole: kernel capability, network declared",
			level:    "network",
			caps:     []Capability{CapExternalTransfer},
			wantFrag: []string{"sandbox.isolation", `"network"`, `"kernel"`, `"external_transfer"`},
		},
		{
			name:     "none declared under a kernel capability",
			level:    "none",
			caps:     []Capability{CapExternalTransfer},
			wantFrag: []string{`"none"`, `"kernel"`, `"external_transfer"`},
		},
		{
			name:     "process declared under a kernel capability",
			level:    "process",
			caps:     []Capability{CapExternalTransfer},
			wantFrag: []string{`"process"`, `"kernel"`, `"external_transfer"`},
		},
		{
			name:     "delete_records also demands kernel",
			level:    "network",
			caps:     []Capability{CapDeleteRecords},
			wantFrag: []string{`"kernel"`, `"delete_records"`},
		},
		{
			name:     "spawn_subagent also demands kernel",
			level:    "process",
			caps:     []Capability{CapSpawnSubagent},
			wantFrag: []string{`"kernel"`, `"spawn_subagent"`},
		},
		{
			name:     "a network capability floors a process declaration",
			level:    "process",
			caps:     []Capability{CapSendEmail},
			wantFrag: []string{`"network"`, `"send_email"`},
		},
		{
			name:     "a process capability floors a none declaration",
			level:    "none",
			caps:     []Capability{CapReadFile},
			wantFrag: []string{`"process"`, `"read_file"`},
		},
		{
			// The driver is not the first capability declared.
			name:     "names the capability that drove the floor, not the first",
			level:    "none",
			caps:     []Capability{CapReadFile, CapSendEmail},
			wantFrag: []string{`"network"`, `"send_email"`},
		},
		{
			// The driver is neither first nor last.
			name:     "names the driver from the middle of the list",
			level:    "process",
			caps:     []Capability{CapWebSearch, CapDeleteRecords, CapWriteFile},
			wantFrag: []string{`"kernel"`, `"delete_records"`},
		},
		{
			// Naming one of several would make "drop that capability" a lie.
			name:     "names every capability sitting at the floor",
			level:    "none",
			caps:     []Capability{CapExternalTransfer, CapWebSearch, CapDeleteRecords},
			wantFrag: []string{"capabilities", `"external_transfer"`, `"delete_records"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse(floorAgentfile(tt.level, tt.caps...))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil (the Agentfile is well-formed)", err)
			}

			// The parser must preserve what was authored. Raising the level
			// to the floor here would run the agent behind a boundary nobody
			// wrote; the refusal belongs to Validate.
			if m.Sandbox.IsolationInferred {
				t.Error("an explicitly written level must not be marked inferred")
			}
			if string(m.Sandbox.Isolation) != tt.level {
				t.Errorf("Parse() rewrote the declared level to %q, want %q left as authored",
					m.Sandbox.Isolation, tt.level)
			}

			err = m.Validate()
			if err == nil {
				t.Fatalf("Validate() error = nil for isolation %q under %v — "+
					"a declared level weaker than its capabilities require must fail closed",
					tt.level, tt.caps)
			}
			for _, want := range tt.wantFrag {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error should mention %s, got: %v", want, err)
				}
			}
		})
	}
}

// TestValidateAcceptsIsolationAtOrAboveCapabilityFloor is the other side of
// that guard: the refusal must not have narrowed what a legitimate Agentfile
// may declare, and must be a FLOOR rather than an equality check. Declaring
// kernel for a file-reading agent is an operator choosing a tighter boundary
// than required — the direction the contract wants.
func TestValidateAcceptsIsolationAtOrAboveCapabilityFloor(t *testing.T) {
	tests := []struct {
		name  string
		level string
		caps  []Capability
	}{
		{"exactly at a kernel floor", "kernel", []Capability{CapExternalTransfer}},
		{"exactly at a network floor", "network", []Capability{CapSendEmail}},
		{"exactly at a process floor", "process", []Capability{CapReadFile}},
		{"one level above the floor", "kernel", []Capability{CapSendEmail}},
		{"two levels above the floor", "kernel", []Capability{CapReadFile}},
		{"above a mixed-capability floor", "kernel", []Capability{CapWebSearch, CapWriteFile}},
		{"no capabilities: none", "none", nil},
		{"no capabilities: process", "process", nil},
		{"no capabilities: network", "network", nil},
		{"no capabilities: kernel", "kernel", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse(floorAgentfile(tt.level, tt.caps...))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if err := m.Validate(); err != nil {
				t.Errorf("Validate() rejected isolation %q under %v: %v", tt.level, tt.caps, err)
			}
			// isolationOrigin() renders this flag as "declared in the
			// Agentfile"; clearing the floor must not turn an operator's own
			// choice into a level Constle claims to have inferred.
			if m.Sandbox.IsolationInferred {
				t.Errorf("isolation %q was declared, not inferred", tt.level)
			}
		})
	}
}

// TestValidateExemptsUnresolvedIsolationFromCapabilityFloor pins the
// pre-inference exemption the floor check inherits from the malformed-level
// check above it. An empty level is not a weak level — it is the state Parse
// fills in — and a manifest built directly in Go may legitimately be validated
// for its policy content before a level is resolved. Dropping the guard is the
// simplification that would break every Go-built manifest in the repo.
func TestValidateExemptsUnresolvedIsolationFromCapabilityFloor(t *testing.T) {
	m := &AgentManifest{
		APIVersion:   "constle.dev/v1alpha1",
		Kind:         "AgentManifest",
		Identity:     Identity{Name: "unresolved-agent"},
		Capabilities: []Capability{CapExternalTransfer},
	}

	if err := m.Validate(); err != nil {
		t.Errorf("Validate() rejected an unresolved isolation level: %v", err)
	}
}

// TestMalformedIsolationOutranksTheCapabilityFloor pins the first half of the
// check's placement. Satisfies fails closed on an invalid operand, so a floor
// check running before the malformed-level check answers `isolation: kernal`
// with "weaker than kernel" — telling an author to raise a level they already
// wrote, instead of naming the typo.
//
// The negative assertion is the whole point: the wrong ordering still REFUSES
// the manifest, and its message still happens to contain both
// "sandbox.isolation" and "kernal", so every pre-existing test passes under it.
func TestMalformedIsolationOutranksTheCapabilityFloor(t *testing.T) {
	m, err := Parse(floorAgentfile("kernal", CapExternalTransfer))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	err = m.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want a rejection for isolation: kernal")
	}
	for _, want := range []string{"unknown isolation level", "kernal"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "weaker") {
		t.Errorf("the capability floor reported a typo'd level as too weak — "+
			"the malformed-level check must run first, got: %v", err)
	}
}

// TestUnknownCapabilityOutranksTheCapabilityFloor pins the second half.
// minIsolationFor maps anything it does not recognize to "process", so a floor
// computed before the unknown-capability loop answers a typo'd capability by
// quoting it back as the reason the level is too weak — naming a capability
// that does not exist, instead of reporting the typo it is.
//
// Negative assertion for the same reason as above: the wrong ordering also
// refuses the manifest, just with the less useful diagnosis.
func TestUnknownCapabilityOutranksTheCapabilityFloor(t *testing.T) {
	m, err := Parse(floorAgentfile("none", Capability("reed_file")))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	err = m.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want a rejection for an unknown capability")
	}
	for _, want := range []string{"unknown capability", "reed_file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "sandbox.isolation") {
		t.Errorf("the capability floor was computed from an unvalidated capability — "+
			"the unknown-capability check must run first, got: %v", err)
	}
}

// TestCapabilityFloorNamesEveryDrivingCapability covers the helper directly.
// The error text depends on two properties nothing else pins: that the
// capabilities named are the ones actually AT the floor (not merely the first
// or last declared), and that there is always at least one of them whenever a
// refusal is possible — otherwise the message prints `capability ""`.
func TestCapabilityFloorNamesEveryDrivingCapability(t *testing.T) {
	tests := []struct {
		name        string
		caps        []Capability
		wantLevel   IsolationLevel
		wantDrivers []Capability
	}{
		{"nil", nil, IsolationNone, nil},
		{"empty", []Capability{}, IsolationNone, nil},
		{"read_file alone", []Capability{CapReadFile}, IsolationProcess, []Capability{CapReadFile}},
		{"write_file alone", []Capability{CapWriteFile}, IsolationProcess, []Capability{CapWriteFile}},
		{"web_search alone", []Capability{CapWebSearch}, IsolationNetwork, []Capability{CapWebSearch}},
		{"external_api alone", []Capability{CapExternalAPI}, IsolationNetwork, []Capability{CapExternalAPI}},
		{"send_email alone", []Capability{CapSendEmail}, IsolationNetwork, []Capability{CapSendEmail}},
		{"spawn_subagent alone", []Capability{CapSpawnSubagent}, IsolationKernel, []Capability{CapSpawnSubagent}},
		{"external_transfer alone", []Capability{CapExternalTransfer}, IsolationKernel, []Capability{CapExternalTransfer}},
		{"delete_records alone", []Capability{CapDeleteRecords}, IsolationKernel, []Capability{CapDeleteRecords}},
		{
			name:        "weaker capabilities are dropped when a stronger one appears",
			caps:        []Capability{CapReadFile, CapWebSearch, CapExternalTransfer},
			wantLevel:   IsolationKernel,
			wantDrivers: []Capability{CapExternalTransfer},
		},
		{
			name:        "a later capability at the same level joins",
			caps:        []Capability{CapExternalTransfer, CapWebSearch, CapDeleteRecords},
			wantLevel:   IsolationKernel,
			wantDrivers: []Capability{CapExternalTransfer, CapDeleteRecords},
		},
		{
			name:        "all three kernel capabilities, in declaration order",
			caps:        []Capability{CapDeleteRecords, CapSpawnSubagent, CapExternalTransfer},
			wantLevel:   IsolationKernel,
			wantDrivers: []Capability{CapDeleteRecords, CapSpawnSubagent, CapExternalTransfer},
		},
		{
			name:        "the weaker capability is not named",
			caps:        []Capability{CapSendEmail, CapReadFile},
			wantLevel:   IsolationNetwork,
			wantDrivers: []Capability{CapSendEmail},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, drivers := capabilityFloor(tt.caps)
			if level != tt.wantLevel {
				t.Errorf("capabilityFloor(%v) level = %q, want %q", tt.caps, level, tt.wantLevel)
			}
			if len(drivers) != len(tt.wantDrivers) {
				t.Fatalf("capabilityFloor(%v) drivers = %v, want %v", tt.caps, drivers, tt.wantDrivers)
			}
			for i := range drivers {
				if drivers[i] != tt.wantDrivers[i] {
					t.Errorf("capabilityFloor(%v) drivers = %v, want %v", tt.caps, drivers, tt.wantDrivers)
					break
				}
			}

			// The invariant the refusal message rests on.
			if level != IsolationNone && len(drivers) == 0 {
				t.Errorf("floor %q has no driving capability — the refusal would print an empty name", level)
			}
		})
	}
}

// TestInferIsolationMatchesCapabilityFloor is the single-definition guard.
// Parse fills an omitted level from InferIsolation and Validate holds a
// declared one to capabilityFloor; if those two ever answer differently, the
// hole reopens for whichever capability they disagree about, silently and with
// nothing failing. Exhaustive over every defined capability and every ordered
// pair of them.
func TestInferIsolationMatchesCapabilityFloor(t *testing.T) {
	all := []Capability{
		CapReadFile, CapWriteFile,
		CapWebSearch, CapExternalAPI,
		CapSendEmail, CapSpawnSubagent,
		CapExternalTransfer, CapDeleteRecords,
	}

	check := func(caps []Capability) {
		t.Helper()
		level, _ := capabilityFloor(caps)
		if got := InferIsolation(caps); got != level {
			t.Errorf("InferIsolation(%v) = %q, but capabilityFloor said %q — "+
				"the level Constle infers and the level it enforces must be the same", caps, got, level)
		}
	}

	check(nil)
	check([]Capability{})
	check(all)

	for _, a := range all {
		// Every defined capability must raise the floor above "none" and name
		// itself: a capability that floored at "none" would be unnameable in
		// the refusal, and one that named nothing would print `capability ""`.
		level, drivers := capabilityFloor([]Capability{a})
		if level == IsolationNone {
			t.Errorf("capability %q floors at %q — no capability may rank as no requirement at all", a, level)
		}
		if len(drivers) != 1 || drivers[0] != a {
			t.Errorf("capabilityFloor([%q]) drivers = %v, want exactly [%q]", a, drivers, a)
		}

		for _, b := range all {
			check([]Capability{a, b})
		}
	}
}
