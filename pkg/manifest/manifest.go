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
	RequireApprovalFor []string `yaml:"require_approval_for,omitempty"`

	// OnTimeout controls what happens if approval is not received in time: "abort" or "proceed".
	// Default is "abort".
	OnTimeout string `yaml:"on_timeout,omitempty"`
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
