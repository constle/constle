package manifest

import (
	"fmt"
	"os"

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

	return nil
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
