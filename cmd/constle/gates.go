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

// warnUnenforcedHumanGates prints a warning when an Agentfile declares human
// approval gates (human_gates.enabled: true, or a non-empty
// require_approval_for) because this version of the runtime has no
// gate-enforcement engine: no action interception, no blocking, no approval
// webhook delivery. Like the kernel-isolation downgrade warning in
// sandbox.DetectBestBackend, a declared protection must never look real when
// it isn't.
//
// Writes bypass printf so tests can swap the writer, but hold stdoutMu
// directly to preserve the stdout serialisation invariant documented on
// printf.
func warnUnenforcedHumanGates(gates manifest.HumanGates) {
	if !gates.Enabled && len(gates.RequireApprovalFor) == 0 {
		return
	}

	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	fmt.Fprintln(gatesWarnOut, "⚠️  warning: human_gates declared but NOT enforced by this version of constle:")
	fmt.Fprintln(gatesWarnOut, "   the runtime has no gate-enforcement engine yet — no action interception,")
	fmt.Fprintln(gatesWarnOut, "   no blocking, and no approval webhook delivery")
	if len(gates.RequireApprovalFor) > 0 {
		fmt.Fprintf(gatesWarnOut, "   actions listed in require_approval_for will run WITHOUT approval: %s\n",
			strings.Join(gates.RequireApprovalFor, ", "))
	}
	fmt.Fprintln(gatesWarnOut)
}
