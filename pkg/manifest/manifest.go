package manifest

// IsolationLevel defines the required sandbox isolation for an agent.
// Values are ordered from weakest to strongest; Constle always picks the highest required.
type IsolationLevel string

const (
	// IsolationNone — no isolation. Development only; never for production.
	IsolationNone IsolationLevel = "none"

	// IsolationProcess — process-level separation. For agents that only read/write files.
	IsolationProcess IsolationLevel = "process"

	// IsolationNetwork — network + process isolation. For agents that access the internet.
	IsolationNetwork IsolationLevel = "network"

	// IsolationKernel — full hardware-level isolation (Firecracker).
	// Required when the agent can transfer money, delete data, or spawn sub-agents.
	IsolationKernel IsolationLevel = "kernel"
)

// Capability declares a named action the agent may perform.
// Constle infers the required IsolationLevel from the declared capabilities.
type Capability string

const (
	CapReadFile         Capability = "read_file"
	CapWriteFile        Capability = "write_file"
	CapWebSearch        Capability = "web_search"
	CapExternalAPI      Capability = "external_api"
	CapSendEmail        Capability = "send_email"
	CapSpawnSubagent    Capability = "spawn_subagent"
	CapExternalTransfer Capability = "external_transfer"
	CapDeleteRecords    Capability = "delete_records"
)

// AgentManifest is the top-level struct for a parsed agent.yaml.
type AgentManifest struct {
	APIVersion   string       `yaml:"apiVersion"`
	Kind         string       `yaml:"kind"`
	Identity     Identity     `yaml:"identity"`
	Sandbox      Sandbox      `yaml:"sandbox"`
	Capabilities []Capability `yaml:"capabilities"`
	MCP          MCP          `yaml:"mcp"`
	A2A          A2A          `yaml:"a2a"`
	Spending     Spending     `yaml:"spending"`
	Limits       Limits       `yaml:"limits"`
	HumanGates   HumanGates   `yaml:"human_gates"`
	Compliance   Compliance   `yaml:"compliance"`
	Metadata     Metadata     `yaml:"metadata"`
}

// Identity identifies the agent.
type Identity struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	// Owner is the email of the person responsible for this agent. Optional.
	Owner string `yaml:"owner,omitempty"`

	// DID is the agent's did:key identifier — the public half of a local
	// Ed25519 identity created with `constle identity create`. When set,
	// every audit log entry is signed and hash-chained with that identity,
	// and `constle run` refuses to start unless the matching private key
	// exists locally (fail closed — a declared identity must never look
	// real when it isn't).
	//
	// Only the public DID appears here. The private key lives under
	// ~/.constle/identities/<name>/ and is never embedded in the Agentfile,
	// following the same indirection pattern as url_secret_ref.
	DID string `yaml:"did,omitempty"`
}

// Sandbox describes how to run the agent in isolation.
type Sandbox struct {
	// Isolation is the required level. When empty, Constle infers it from Capabilities.
	Isolation IsolationLevel `yaml:"isolation,omitempty"`

	// Image is the Docker image to run (e.g. "python:3.11-slim").
	Image string `yaml:"image,omitempty"`

	// Command overrides the image CMD.
	Command []string `yaml:"command,omitempty"`

	// MemoryMB is the memory limit. Default: 512.
	MemoryMB int `yaml:"memory_mb,omitempty"`

	// DiskMB is the disk limit. Default: 2048.
	DiskMB int `yaml:"disk_mb,omitempty"`

	Network Network `yaml:"network"`
}

// Network defines egress policy.
type Network struct {
	// Egress is "restricted" (allowlist), "open", or "none".
	Egress string `yaml:"egress"`

	// AllowedHosts lists permitted destinations when Egress is "restricted".
	AllowedHosts []string `yaml:"allowed_hosts,omitempty"`
}

// MCP declares the Model Context Protocol servers the agent may call.
//
// Every declared MCP call is routed through the constle gate proxy — a
// protocol-aware chokepoint analogous to Squid for HTTP egress. The agent
// receives only the proxy address (CONSTLE_MCP_<ID>_URL); the real server
// URL never enters the sandbox, and the sandbox network policy blocks any
// direct path to it.
type MCP struct {
	Servers []MCPServer `yaml:"servers,omitempty"`
}

// MCPServer describes one MCP server the agent may call through the gate proxy.
type MCPServer struct {
	// ID is a unique name for this server, used in audit events and in the
	// CONSTLE_MCP_<ID>_URL environment variable ("-" becomes "_", uppercased).
	// Lowercase letters, digits, hyphens, and underscores only.
	ID string `yaml:"id"`

	// URL is the real streamable-HTTP endpoint of the MCP server.
	// Only visible on the host side — never forwarded into the sandbox.
	URL string `yaml:"url"`

	// Tools is an optional allowlist of tool names the agent may call on this
	// server. Empty means every tool passes through (gated tools still gate).
	Tools []string `yaml:"tools,omitempty"`
}

// A2A declares signed agent-to-agent communication with explicitly known
// peers.
//
// Every peer is declared here by the operator (DID + endpoint, exchanged out
// of band). There is deliberately NO discovery mechanism: an agent can only
// ever exchange A2A calls with peers written into this file.
//
// All A2A traffic is signed and verified in the HOST constle process using
// the agent's local identity — identity.did is therefore required. The
// sandbox never signs, never verifies, and never sees a peer's real
// endpoint: it talks only to the per-run A2A gate (CONSTLE_A2A_URL), the
// same trust model as the MCP gate proxy applied in the reverse direction.
type A2A struct {
	// Listen is the host-side address ("host:port" or ":port") on which the
	// constle process accepts inbound calls from declared peers. The listener
	// runs on the host, never inside the sandbox; only calls that pass
	// signature verification AND appear in Peers are relayed to the agent.
	// Empty means this agent makes outbound A2A calls only.
	Listen string `yaml:"listen,omitempty"`

	// Peers lists the only agents this agent may exchange A2A calls with —
	// both as outbound targets and as authorized inbound senders.
	Peers []A2APeer `yaml:"peers,omitempty"`
}

// A2APeer is one explicitly declared peer agent.
type A2APeer struct {
	// Name is the local alias for this peer, used in gate URLs and audit
	// events. Lowercase letters, digits, hyphens, and underscores only.
	Name string `yaml:"name"`

	// DID is the peer's did:key identifier. The verification key for every
	// message from (and to) this peer is recovered from this string alone.
	DID string `yaml:"did"`

	// Endpoint is the peer's public A2A URL — its host process's a2a.listen
	// address. Only visible on the host side; never forwarded into the
	// sandbox.
	Endpoint string `yaml:"endpoint"`
}

// Spending declares cost limits. Empty means the operator sets them at runtime.
type Spending struct {
	MaxPerRunUSD   string `yaml:"max_per_run_usd,omitempty"`
	MaxPerDayUSD   string `yaml:"max_per_day_usd,omitempty"`
	MaxPerMonthUSD string `yaml:"max_per_month_usd,omitempty"`
}

// Limits defines runtime constraints actively enforced by constle.
type Limits struct {
	// MaxDurationSeconds is the maximum wall-clock run time.
	// When elapsed, constle sends docker stop and records a terminated_by_limit audit event.
	// 0 means no limit.
	MaxDurationSeconds int `yaml:"max_duration_seconds,omitempty"`
}

// HumanGates controls when the agent must pause for human approval.
type HumanGates struct {
	// Enabled — when false the agent runs fully autonomously (not recommended for production).
	Enabled bool `yaml:"enabled"`

	// RequireApprovalFor lists actions that must be approved before execution.
	//
	// MAPPING CONTRACT: an entry gates an MCP tool call when it is an exact,
	// case-sensitive match for the tool name (the params.name of a tools/call
	// request) on any server declared under mcp.servers. The tool name is the
	// only protocol-level identifier the gate proxy observes, and exact match
	// is the only deterministic, auditable mapping — no semantic guessing.
	// Entries that match no declared MCP tool are NOT enforced and are called
	// out with a warning at run and validate time.
	RequireApprovalFor []string `yaml:"require_approval_for,omitempty"`

	// ApprovalTimeoutSeconds is how long a gated call waits for a human
	// decision before OnTimeout applies. Default is 300.
	ApprovalTimeoutSeconds int `yaml:"approval_timeout_seconds,omitempty"`

	// OnTimeout controls what happens if approval is not received in time: "abort" or "proceed".
	// Default is "abort".
	OnTimeout string `yaml:"on_timeout,omitempty"`

	// Notify lists channels notified when a gate triggers. Only the webhook
	// channel is supported by this version; unsupported channels are a
	// validation error so a declared notification never silently goes nowhere.
	Notify []NotifyChannel `yaml:"notify,omitempty"`
}

// NotifyChannel is one notification target for gate events.
type NotifyChannel struct {
	// Channel is the delivery mechanism. Supported: "webhook".
	Channel string `yaml:"channel"`

	// URLSecretRef names the environment variable holding the webhook URL.
	// Indirection keeps secrets out of the committed Agentfile.
	URLSecretRef string `yaml:"url_secret_ref,omitempty"`
}

// Compliance captures regulatory and audit requirements.
type Compliance struct {
	// AuditLogLevel is one of: none, minimal, standard, verbose.
	AuditLogLevel string `yaml:"audit_log_level,omitempty"`

	// Frameworks lists regulatory frameworks the deployment must satisfy.
	Frameworks []string `yaml:"frameworks,omitempty"`

	GeoRestrictions GeoRestrictions `yaml:"geo_restrictions,omitempty"`
}

// GeoRestrictions limits where the agent may run.
type GeoRestrictions struct {
	AllowedRegions []string `yaml:"allowed_regions,omitempty"`
	DeniedRegions  []string `yaml:"denied_regions,omitempty"`
}

// Metadata holds descriptive fields not enforced by the runtime.
type Metadata struct {
	Description string            `yaml:"description,omitempty"`
	Author      string            `yaml:"author,omitempty"`
	License     string            `yaml:"license,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
}
