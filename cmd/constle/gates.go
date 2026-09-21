package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/constle/constle/pkg/manifest"
)

// gatesWarnOut is where warnUnenforcedHumanGates prints. It is a package
// variable so tests can capture the output (same pattern as detectOut in
// internal/sandbox).
var gatesWarnOut io.Writer = os.Stdout

// warnUnenforcedHumanGates warns about the require_approval_for entries the
// gate engine cannot enforce for this manifest, and says which of the two
// reasons applies: the master switch is off (human_gates.enabled: false, which
// disarms every entry — spec/agent-manifest.md §13.1), or the entry matches no
// declared MCP tool.
//
// Human gates ARE enforced now — for MCP tool calls: an entry that exactly
// matches a tool name on a declared mcp.servers entry pauses that call at
// the gate proxy for approval. What this function reports is the remainder:
// entries that provably match no declared MCP tool (or any entry at all
// when no MCP servers are declared). Like the isolation contract enforced in
// sandbox.DetectBestBackend, a declared protection must never look real when
// it isn't — but a real protection must no longer be reported as missing
// either.
//
// Writes bypass printf so tests can swap the writer, but hold stdoutMu
// directly to preserve the stdout serialisation invariant documented on
// printf.
func warnUnenforcedHumanGates(m *manifest.AgentManifest) {
	gates := m.HumanGates
	if len(gates.RequireApprovalFor) == 0 {
		return
	}

	// The master switch and the tool mapping are two different reasons for the
	// same outcome, and they need two different messages. Reporting a disabled
	// gate as "matches no tool on any declared MCP server" sends an operator
	// hunting for a tool-name typo that isn't there, while the one line that
	// would fix it — enabled: true — goes unmentioned.
	if !gates.GatesArmed() {
		lines := []string{
			"⚠️  warning: human_gates.enabled is false — NO gate is enforced:",
			fmt.Sprintf("   these require_approval_for entries will run WITHOUT approval: %s",
				strings.Join(gates.RequireApprovalFor, ", ")),
			"   set human_gates.enabled: true to enforce them",
		}
		stdoutMu.Lock()
		defer stdoutMu.Unlock()
		warnBlock(gatesWarnOut, lines)
		return
	}

	_, unenforced := m.EnforcedGateEntries()
	if len(unenforced) == 0 {
		return
	}

	lines := []string{
		"⚠️  warning: some human_gates entries are NOT enforced:",
		"   these require_approval_for entries match no tool on any declared MCP server",
		fmt.Sprintf("   and will run WITHOUT approval: %s", strings.Join(unenforced, ", ")),
	}
	if len(m.MCP.Servers) == 0 {
		lines = append(lines,
			"   (no mcp.servers are declared — gates are enforced on MCP tool calls,",
			"   matched by exact tool name)")
	}

	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	warnBlock(gatesWarnOut, lines)
}
