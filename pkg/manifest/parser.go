package manifest

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseFile reads a YAML file from disk and returns an AgentManifest.
func ParseFile(path string) (*AgentManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read Agentfile at %q: %w", path, err)
	}

	return Parse(data)
}

// Parse unmarshals YAML bytes into an AgentManifest.
// Useful for tests — callers can supply YAML directly without a file.
func Parse(data []byte) (*AgentManifest, error) {
	var m AgentManifest

	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid YAML in Agentfile: %w", err)
	}

	// If isolation is not set explicitly, infer it from the declared capabilities.
	if m.Sandbox.Isolation == "" {
		m.Sandbox.Isolation = InferIsolation(m.Capabilities)
	}

	if m.Sandbox.MemoryMB == 0 {
		m.Sandbox.MemoryMB = 512
	}
	if m.Sandbox.DiskMB == 0 {
		m.Sandbox.DiskMB = 2048
	}
	if m.Sandbox.Network.Egress == "" {
		m.Sandbox.Network.Egress = "restricted"
	}
	if m.HumanGates.OnTimeout == "" {
		m.HumanGates.OnTimeout = "abort"
	}
	if m.HumanGates.ApprovalTimeoutSeconds == 0 {
		m.HumanGates.ApprovalTimeoutSeconds = 300
	}
	if m.Compliance.AuditLogLevel == "" {
		m.Compliance.AuditLogLevel = "standard"
	}

	return &m, nil
}

// Validate checks that the manifest contains all required fields.
func (m *AgentManifest) Validate() error {
	if m.APIVersion != "constle.dev/v1alpha1" {
		return fmt.Errorf(
			"unsupported apiVersion %q — expected \"constle.dev/v1alpha1\"",
			m.APIVersion,
		)
	}

	if m.Kind != "AgentManifest" {
		return fmt.Errorf(
			"unsupported kind %q — expected \"AgentManifest\"",
			m.Kind,
		)
	}

	if m.Identity.Name == "" {
		return fmt.Errorf("identity.name is required")
	}

	for _, cap := range m.Capabilities {
		if !isKnownCapability(cap) {
			return fmt.Errorf("unknown capability %q — check the Constle docs for supported capabilities", cap)
		}
	}

	if err := m.validateMCP(); err != nil {
		return err
	}

	if err := m.validateHumanGates(); err != nil {
		return err
	}

	return nil
}

// validateMCP checks the declared MCP servers and, critically, that no
// network allowlist entry opens a direct path from the sandbox to a real
// MCP server — that would let the agent bypass the gate proxy entirely, so
// it fails closed as a validation error rather than a warning.
func (m *AgentManifest) validateMCP() error {
	seen := map[string]bool{}

	for _, srv := range m.MCP.Servers {
		if srv.ID == "" {
			return fmt.Errorf("mcp.servers: every server needs an id")
		}
		if !isValidMCPServerID(srv.ID) {
			return fmt.Errorf("mcp.servers: invalid id %q — use lowercase letters, digits, hyphens, and underscores", srv.ID)
		}
		if seen[srv.ID] {
			return fmt.Errorf("mcp.servers: duplicate id %q", srv.ID)
		}
		seen[srv.ID] = true

		host, err := mcpServerHost(srv.URL)
		if err != nil {
			return fmt.Errorf("mcp.servers[%s]: %w", srv.ID, err)
		}

		for _, allowed := range m.Sandbox.Network.AllowedHosts {
			if hostsOverlap(allowed, host) {
				return fmt.Errorf(
					"mcp.servers[%s]: host %q also appears in network.allowed_hosts — "+
						"that would let the agent reach the MCP server directly, bypassing the gate proxy; "+
						"remove it from allowed_hosts (MCP traffic is routed through the gate automatically)",
					srv.ID, host,
				)
			}
		}
	}

	// The gate transport itself must not be reachable beyond the gate port:
	// allowing these hosts wholesale through Squid would expose every host
	// service to the sandbox, including a locally-run MCP server.
	if len(m.MCP.Servers) > 0 {
		for _, allowed := range m.Sandbox.Network.AllowedHosts {
			if isHostLoopbackAlias(allowed) {
				return fmt.Errorf(
					"network.allowed_hosts: %q must not be allowlisted when mcp.servers are declared — "+
						"it would expose host services (including local MCP servers) directly to the agent, bypassing the gate proxy",
					allowed,
				)
			}
		}
	}

	return nil
}

// validateHumanGates checks gate timing and notification channels.
func (m *AgentManifest) validateHumanGates() error {
	g := m.HumanGates

	if g.ApprovalTimeoutSeconds < 0 {
		return fmt.Errorf("human_gates.approval_timeout_seconds must be positive, got %d", g.ApprovalTimeoutSeconds)
	}

	switch g.OnTimeout {
	case "", "abort", "proceed":
	default:
		return fmt.Errorf("human_gates.on_timeout must be \"abort\" or \"proceed\", got %q", g.OnTimeout)
	}

	for _, n := range g.Notify {
		// Unsupported channels are an error, not a warning: a declared
		// notification path must never look real when it isn't.
		if n.Channel != "webhook" {
			return fmt.Errorf("human_gates.notify: channel %q is not supported by this version of constle (supported: webhook)", n.Channel)
		}
		if n.URLSecretRef == "" {
			return fmt.Errorf("human_gates.notify: webhook channel requires url_secret_ref (the env var holding the webhook URL)")
		}
	}

	return nil
}

// EnforcedGateEntries splits require_approval_for into entries that map to a
// declared MCP tool (enforced by the gate proxy) and entries that provably
// match nothing (unenforced — surfaced as a warning by the CLI).
//
// An entry is "possibly enforced" when any declared server omits its tools
// allowlist: the runtime match is exact on the tool name of every tools/call,
// so such an entry may still gate a real call. Only entries that cannot match
// under any declared server are reported as unenforced.
func (m *AgentManifest) EnforcedGateEntries() (enforced, unenforced []string) {
	anyServerWithoutToolList := false
	declaredTools := map[string]bool{}
	for _, srv := range m.MCP.Servers {
		if len(srv.Tools) == 0 {
			anyServerWithoutToolList = true
		}
		for _, tool := range srv.Tools {
			declaredTools[tool] = true
		}
	}

	for _, entry := range m.HumanGates.RequireApprovalFor {
		switch {
		case declaredTools[entry]:
			enforced = append(enforced, entry)
		case anyServerWithoutToolList:
			// May match at runtime; counted as enforced for warning purposes.
			enforced = append(enforced, entry)
		default:
			unenforced = append(unenforced, entry)
		}
	}
	return enforced, unenforced
}

// mcpServerHost extracts and validates the host of an MCP server URL.
func mcpServerHost(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("url is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid url %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("url %q must use http or https (streamable HTTP is the only supported MCP transport)", rawURL)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("url %q has no host", rawURL)
	}
	return u.Hostname(), nil
}

// hostsOverlap reports whether an allowed_hosts entry covers the given host.
// Squid dstdomain entries starting with "." match all subdomains.
func hostsOverlap(allowed, host string) bool {
	if strings.HasPrefix(allowed, ".") {
		return host == strings.TrimPrefix(allowed, ".") || strings.HasSuffix(host, allowed)
	}
	return allowed == host
}

// isHostLoopbackAlias reports whether an allowlist entry addresses the
// sandbox host itself — the gate proxy's transport surface.
func isHostLoopbackAlias(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "host.docker.internal", ".host.docker.internal":
		return true
	}
	return false
}

// isValidMCPServerID enforces the id charset documented on MCPServer.ID —
// the id is embedded in an environment variable name and in URLs.
func isValidMCPServerID(id string) bool {
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// InferIsolation returns the strongest IsolationLevel required by any of the
// given capabilities.
func InferIsolation(caps []Capability) IsolationLevel {
	highest := IsolationNone

	for _, cap := range caps {
		required := minIsolationFor(cap)
		if isolationRank(required) > isolationRank(highest) {
			highest = required
		}
	}

	return highest
}

// RequiresHumanGate reports whether the capability involves an irreversible
// action that requires human approval (payments, email, deletion, sub-agents).
func RequiresHumanGate(cap Capability) bool {
	switch cap {
	case CapExternalTransfer, CapSendEmail, CapDeleteRecords, CapSpawnSubagent:
		return true
	default:
		return false
	}
}

// InferRequiredGates returns the list of capability names that require a human
// gate, derived from the declared capabilities.
func InferRequiredGates(caps []Capability) []string {
	var gates []string
	for _, cap := range caps {
		if RequiresHumanGate(cap) {
			gates = append(gates, string(cap))
		}
	}
	return gates
}

// minIsolationFor returns the minimum IsolationLevel required for a capability.
func minIsolationFor(cap Capability) IsolationLevel {
	switch cap {
	case CapReadFile, CapWriteFile:
		return IsolationProcess

	case CapWebSearch, CapExternalAPI:
		return IsolationNetwork

	case CapSendEmail:
		return IsolationNetwork

	case CapExternalTransfer, CapDeleteRecords, CapSpawnSubagent:
		return IsolationKernel

	default:
		return IsolationProcess
	}
}

// isolationRank returns a numeric rank for comparison. Higher = stronger isolation.
func isolationRank(level IsolationLevel) int {
	switch level {
	case IsolationNone:
		return 0
	case IsolationProcess:
		return 1
	case IsolationNetwork:
		return 2
	case IsolationKernel:
		return 3
	default:
		return 0
	}
}

func isKnownCapability(cap Capability) bool {
	known := []Capability{
		CapReadFile, CapWriteFile,
		CapWebSearch, CapExternalAPI,
		CapSendEmail, CapSpawnSubagent,
		CapExternalTransfer, CapDeleteRecords,
	}
	for _, k := range known {
		if cap == k {
			return true
		}
	}
	return false
}
