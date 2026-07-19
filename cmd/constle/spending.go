package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/spending"
	"github.com/constle/constle/pkg/manifest"
)

// spendingWarnOut is where warnUnenforcedSpending prints. Package variable
// so tests can capture the output — same pattern as gatesWarnOut.
var spendingWarnOut io.Writer = os.Stdout

// warnUnenforcedSpending warns about every spending declaration the runtime
// cannot actually enforce for this manifest. Same principle as
// warnUnenforcedHumanGates: a declared protection must never look real when
// it isn't.
//
// Cost is metered ONLY at the MCP gate proxy, for servers that declare a
// pricing block — Constle deliberately does not TLS-intercept generic
// allowed_hosts traffic (that would let it read everything the agent says,
// far beyond what cost metering needs). So:
//
//   - limits without any priced mcp.servers entry are NOT enforced at all;
//   - limits with priced servers are enforced for those servers' traffic,
//     while allowed_hosts traffic stays unmetered — said out loud, never
//     silently counted as $0;
//   - max_per_month_usd is not enforced by this version of constle.
func warnUnenforcedSpending(m *manifest.AgentManifest) {
	s := m.Spending
	limitsDeclared := s.MaxPerRunUSD != "" || s.MaxPerDayUSD != ""
	priced := m.PricedMCPServers()

	var lines []string

	if limitsDeclared && len(priced) == 0 {
		lines = append(lines,
			"⚠️  warning: spending limits are declared but NOT enforced:",
			"   no mcp.servers entry declares a pricing block, so there is nothing to meter.",
			"   cost is measured only at the MCP gate proxy (constle does not TLS-intercept",
			"   generic allowed_hosts traffic); declare pricing on the MCP servers that cost money.",
		)
	}

	if limitsDeclared && len(priced) > 0 && len(m.Sandbox.Network.AllowedHosts) > 0 {
		lines = append(lines,
			"⚠️  warning: spending limits are enforced ONLY for priced MCP servers ("+strings.Join(priced, ", ")+");",
			"   traffic to network.allowed_hosts ("+strings.Join(m.Sandbox.Network.AllowedHosts, ", ")+")",
			"   is NOT metered and does not count toward the limits.",
		)
	}

	if s.MaxPerMonthUSD != "" {
		lines = append(lines,
			"⚠️  warning: spending.max_per_month_usd is NOT enforced by this version of constle.")
	}

	if !limitsDeclared && len(priced) > 0 {
		lines = append(lines,
			"⚠️  warning: mcp.servers declare pricing but no spending limits are set —",
			"   usage is metered, but nothing is enforced. declare spending.max_per_run_usd",
			"   and/or spending.max_per_day_usd.",
		)
	}

	if len(lines) == 0 {
		return
	}

	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	for _, l := range lines {
		fmt.Fprintln(spendingWarnOut, l)
	}
	fmt.Fprintln(spendingWarnOut)
}

// buildSpendingTracker builds the run's spending tracker, or nil when no
// MCP server declares pricing (nothing can be metered — the CLI has already
// warned if limits were declared anyway).
//
// When max_per_day_usd is declared it also opens the durable per-DID daily
// ledger and FAILS CLOSED before the sandbox ever starts if today's
// already-accumulated spend leaves no budget: metering is post-hoc (a
// response's cost is only known once it arrived), so a run started with an
// exhausted budget would be guaranteed to overshoot before the kill lands.
func buildSpendingTracker(m *manifest.AgentManifest, logger *audit.Logger) (*spending.Tracker, error) {
	if len(m.PricedMCPServers()) == 0 {
		return nil, nil
	}

	var limits spending.Limits
	var err error
	if m.Spending.MaxPerRunUSD != "" {
		if limits.PerRun, err = spending.ParseUSD(m.Spending.MaxPerRunUSD); err != nil {
			return nil, fmt.Errorf("spending.max_per_run_usd: %v", err)
		}
	}
	if m.Spending.MaxPerDayUSD != "" {
		if limits.PerDay, err = spending.ParseUSD(m.Spending.MaxPerDayUSD); err != nil {
			return nil, fmt.Errorf("spending.max_per_day_usd: %v", err)
		}
	}
	limits.WarnAtPctOfDaily = m.Spending.Alerts.WarnAtPctOfDaily

	var store *spending.DailyStore
	if limits.PerDay > 0 {
		store, err = spending.OpenDailyStore(m.Identity.DID)
		if err != nil {
			return nil, err
		}

		prior, err := store.TodayTotal()
		if err != nil {
			// Fail closed: an unreadable ledger is never treated as $0 spent.
			return nil, fmt.Errorf("cannot read today's spending ledger: %w", err)
		}
		if prior >= limits.PerDay {
			logger.Log("", m.Identity.Name, audit.EventSpendingLimit, map[string]any{
				"severity":        "limit",
				"limit":           string(spending.ViolationPerDay),
				"action":          "run_refused",
				"day_total_usd":   prior.USD(),
				"max_per_day_usd": limits.PerDay.USD(),
			})
			return nil, fmt.Errorf(
				"refusing to start: today's accumulated spend ($%s) already meets or exceeds spending.max_per_day_usd ($%s)",
				prior.USD(), limits.PerDay.USD())
		}
	}

	return spending.NewTracker(limits, store)
}
