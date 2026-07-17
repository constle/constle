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
// gate engine cannot enforce for this manifest.
//
// Human gates ARE enforced now — for MCP tool calls: an entry that exactly
// matches a tool name on a declared mcp.servers entry pauses that call at
// the gate proxy for approval. What this function reports is the remainder:
// entries that provably match no declared MCP tool (or any entry at all
// when no MCP servers are declared). Like the kernel-isolation downgrade
// warning in sandbox.DetectBestBackend, a declared protection must never
// look real when it isn't — but a real protection must no longer be
// reported as missing either.
//
// Writes bypass printf so tests can swap the writer, but hold stdoutMu
// directly to preserve the stdout serialisation invariant documented on
// printf.
func warnUnenforcedHumanGates(m *manifest.AgentManifest) {
	gates := m.HumanGates
	if !gates.Enabled && len(gates.RequireApprovalFor) == 0 {
		return
	}

	_, unenforced := m.EnforcedGateEntries()
	if len(unenforced) == 0 {
		return
	}

	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	fmt.Fprintln(gatesWarnOut, "⚠️  warning: some human_gates entries are NOT enforced:")
	fmt.Fprintln(gatesWarnOut, "   these require_approval_for entries match no tool on any declared MCP server")
	fmt.Fprintf(gatesWarnOut, "   and will run WITHOUT approval: %s\n", strings.Join(unenforced, ", "))
	if len(m.MCP.Servers) == 0 {
		fmt.Fprintln(gatesWarnOut, "   (no mcp.servers are declared — gates are enforced on MCP tool calls,")
		fmt.Fprintln(gatesWarnOut, "   matched by exact tool name)")
	}
	fmt.Fprintln(gatesWarnOut)
}
