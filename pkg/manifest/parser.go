package manifest

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/constle/constle/internal/spending"
	"github.com/constle/constle/pkg/did"
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

	if m.Identity.DID != "" {
		if err := did.Validate(m.Identity.DID); err != nil {
			return fmt.Errorf("identity.did: %w", err)
		}
	}

	for _, cap := range m.Capabilities {
		if !isKnownCapability(cap) {
			return fmt.Errorf("unknown capability %q — check the Constle docs for supported capabilities", cap)
		}
	}

	if err := m.validateMCP(); err != nil {
		return err
	}

	if err := m.validateA2A(); err != nil {
		return err
	}

	if err := m.validateHumanGates(); err != nil {
		return err
	}

	if err := m.validateSpending(); err != nil {
		return err
	}

	return nil
}

// validateSpending checks the spending limits and every mcp.servers pricing
// block. Amounts must parse exactly (never rounded silently), and a daily
// cap without a DID fails closed: durable daily tracking is keyed by DID so
// renaming an agent cannot reset it.
func (m *AgentManifest) validateSpending() error {
	s := m.Spending

	for _, f := range []struct{ name, value string }{
		{"spending.max_per_run_usd", s.MaxPerRunUSD},
		{"spending.max_per_day_usd", s.MaxPerDayUSD},
		{"spending.max_per_month_usd", s.MaxPerMonthUSD},
	} {
		if f.value == "" {
			continue
		}
		v, err := spending.ParseUSD(f.value)
		if err != nil {
			return fmt.Errorf("%s: %v", f.name, err)
		}
		if v == 0 {
			// A zero cap would silently read as "unset" at enforcement time —
			// ambiguous, so it fails closed here instead.
			return fmt.Errorf("%s: a cap of 0 is ambiguous — omit the field to leave the limit unset", f.name)
		}
	}

	if s.MaxPerDayUSD != "" && m.Identity.DID == "" {
		return fmt.Errorf(
			"spending.max_per_day_usd: identity.did is required — daily spend is tracked durably per DID "+
				"(tracking by name would let a rename reset it); create one with: constle identity create %s",
			m.Identity.Name)
	}

	if pct := s.Alerts.WarnAtPctOfDaily; pct != 0 {
		if pct < 1 || pct > 100 {
			return fmt.Errorf("spending.alerts.warn_at_pct_of_daily must be between 1 and 100, got %d", pct)
		}
		if s.MaxPerDayUSD == "" {
			return fmt.Errorf("spending.alerts.warn_at_pct_of_daily is set but spending.max_per_day_usd is not — there is no daily cap to warn about")
		}
	}

	for _, srv := range m.MCP.Servers {
		if srv.Pricing == nil {
			continue
		}
		if len(srv.Pricing.Meters) == 0 {
			return fmt.Errorf("mcp.servers[%s].pricing: meters must not be empty — a pricing block without meters cannot measure anything", srv.ID)
		}
		for i, meter := range srv.Pricing.Meters {
			if _, err := spending.ParsePath(meter.UsagePath); err != nil {
				return fmt.Errorf("mcp.servers[%s].pricing.meters[%d]: %v", srv.ID, i, err)
			}
			if _, err := spending.ParseUSD(meter.USDPerUnit); err != nil {
				return fmt.Errorf("mcp.servers[%s].pricing.meters[%d].usd_per_unit: %v", srv.ID, i, err)
			}
		}
	}

	return nil
}

// PricedMCPServers returns the ids of MCP servers that declare a pricing
// block — the servers whose traffic the gate proxy actually meters.
func (m *AgentManifest) PricedMCPServers() []string {
	var ids []string
	for _, srv := range m.MCP.Servers {
		if srv.Pricing != nil {
			ids = append(ids, srv.ID)
		}
	}
	return ids
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
		if !isValidID(srv.ID) {
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

// validateA2A checks the declared A2A configuration and, critically, that no
// network allowlist entry opens a direct sandbox path to a peer's endpoint —
// that would let the agent talk to the peer without the host-side signing
// gate, so it fails closed as a validation error, exactly like the
// mcp.servers bypass check above.
func (m *AgentManifest) validateA2A() error {
	a := m.A2A
	if a.Listen == "" && len(a.Peers) == 0 {
		return nil
	}

	// Every A2A call is signed (outbound) or verified (inbound) with the
	// agent's own identity in the host process — without a declared identity
	// there is no key to sign with, so A2A cannot exist unsigned.
	if m.Identity.DID == "" {
		return fmt.Errorf(
			"a2a: identity.did is required — every A2A call is signed with the agent's identity; "+
				"create one with: constle identity create %s", m.Identity.Name)
	}

	if len(a.Peers) == 0 {
		// listen without peers: no inbound sender could ever be authorized,
		// so the listener would only ever reject. Refuse the configuration
		// rather than run a listener that silently can never accept.
		return fmt.Errorf("a2a.listen is set but a2a.peers is empty — no peer could ever be authorized to call this agent; declare the peers or remove a2a.listen")
	}

	if a.Listen != "" {
		if _, _, err := net.SplitHostPort(a.Listen); err != nil {
			return fmt.Errorf("a2a.listen: invalid listen address %q — use \"host:port\" or \":port\": %v", a.Listen, err)
		}
	}

	seen := map[string]bool{}
	seenDID := map[string]bool{}
	for _, p := range a.Peers {
		if p.Name == "" {
			return fmt.Errorf("a2a.peers: every peer needs a name")
		}
		if !isValidID(p.Name) {
			return fmt.Errorf("a2a.peers: invalid name %q — use lowercase letters, digits, hyphens, and underscores", p.Name)
		}
		if seen[p.Name] {
			return fmt.Errorf("a2a.peers: duplicate name %q", p.Name)
		}
		seen[p.Name] = true

		if p.DID == "" {
			return fmt.Errorf("a2a.peers[%s]: did is required (the peer's did:key, exchanged out of band)", p.Name)
		}
		if err := did.Validate(p.DID); err != nil {
			return fmt.Errorf("a2a.peers[%s]: %w", p.Name, err)
		}
		if seenDID[p.DID] {
			return fmt.Errorf("a2a.peers: two peers declare the same did %q — sender identity would be ambiguous", p.DID)
		}
		seenDID[p.DID] = true
		if p.DID == m.Identity.DID {
			return fmt.Errorf("a2a.peers[%s]: peer did equals this agent's own identity.did", p.Name)
		}

		host, err := a2aEndpointHost(p.Endpoint)
		if err != nil {
			return fmt.Errorf("a2a.peers[%s]: %w", p.Name, err)
		}

		for _, allowed := range m.Sandbox.Network.AllowedHosts {
			if hostsOverlap(allowed, host) {
				return fmt.Errorf(
					"a2a.peers[%s]: host %q also appears in network.allowed_hosts — "+
						"that would let the agent reach the peer directly, bypassing the signing A2A gate; "+
						"remove it from allowed_hosts (A2A traffic is signed and routed through the gate automatically)",
					p.Name, host,
				)
			}
		}
	}

	// The gate transport itself must not be reachable beyond the gate port —
	// same rule as for mcp.servers above.
	for _, allowed := range m.Sandbox.Network.AllowedHosts {
		if isHostLoopbackAlias(allowed) {
			return fmt.Errorf(
				"network.allowed_hosts: %q must not be allowlisted when a2a.peers are declared — "+
					"it would expose host services (including the A2A gate transport) directly to the agent, bypassing signature enforcement",
				allowed,
			)
		}
	}

	return nil
}

// a2aEndpointHost extracts and validates the host of a peer's A2A endpoint URL.
func a2aEndpointHost(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("endpoint is required (the peer's public A2A URL)")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("endpoint %q must use http or https", rawURL)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("endpoint %q has no host", rawURL)
	}
	return u.Hostname(), nil
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

// isValidID enforces the shared id charset documented on MCPServer.ID and
// A2APeer.Name — these ids are embedded in environment variable names, gate
// URLs, and audit events.
func isValidID(id string) bool {
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
