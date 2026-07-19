package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/constle/constle/pkg/manifest"
)

// withCapturedSpendingWarn redirects warnUnenforcedSpending output into a
// buffer for one test — same pattern as withCapturedGatesWarn.
func withCapturedSpendingWarn(t *testing.T) *bytes.Buffer {
	t.Helper()
	orig := spendingWarnOut
	t.Cleanup(func() { spendingWarnOut = orig })
	buf := &bytes.Buffer{}
	spendingWarnOut = buf
	return buf
}

func spendingManifest(spend manifest.Spending, servers []manifest.MCPServer, allowedHosts []string) *manifest.AgentManifest {
	return &manifest.AgentManifest{
		Identity: manifest.Identity{Name: "spend-warning-test"},
		Sandbox: manifest.Sandbox{
			Network: manifest.Network{Egress: "restricted", AllowedHosts: allowedHosts},
		},
		Spending: spend,
		MCP:      manifest.MCP{Servers: servers},
	}
}

var pricedServer = manifest.MCPServer{
	ID:  "llm",
	URL: "http://127.0.0.1:9/mcp",
	Pricing: &manifest.MCPPricing{Meters: []manifest.PriceMeter{
		{UsagePath: "result.usage.tokens", USDPerUnit: "0.000003"},
	}},
}

// TestWarnSpendingLimitsWithoutPricing is the deliverable check: limits
// without priced servers must produce an explicit NOT-enforced warning —
// never silently do nothing.
func TestWarnSpendingLimitsWithoutPricing(t *testing.T) {
	buf := withCapturedSpendingWarn(t)

	warnUnenforcedSpending(spendingManifest(
		manifest.Spending{MaxPerRunUSD: "0.50"},
		[]manifest.MCPServer{{ID: "plain", URL: "http://127.0.0.1:9/mcp"}},
		[]string{"api.example.com"},
	))

	out := buf.String()
	if !strings.Contains(out, "NOT enforced") {
		t.Errorf("expected a NOT-enforced warning, got:\n%s", out)
	}
	if !strings.Contains(out, "pricing") {
		t.Errorf("warning should explain that pricing is missing:\n%s", out)
	}
}

// TestWarnAllowedHostsNotMetered: even with priced servers, allowed_hosts
// traffic is not counted — the warning must say so out loud.
func TestWarnAllowedHostsNotMetered(t *testing.T) {
	buf := withCapturedSpendingWarn(t)

	warnUnenforcedSpending(spendingManifest(
		manifest.Spending{MaxPerRunUSD: "0.50"},
		[]manifest.MCPServer{pricedServer},
		[]string{"api.example.com"},
	))

	out := buf.String()
	if !strings.Contains(out, "NOT metered") {
		t.Errorf("expected an allowed_hosts-not-metered warning, got:\n%s", out)
	}
	if !strings.Contains(out, "api.example.com") {
		t.Errorf("warning should name the unmetered hosts:\n%s", out)
	}
}

func TestWarnMonthlyCapUnenforced(t *testing.T) {
	buf := withCapturedSpendingWarn(t)
	warnUnenforcedSpending(spendingManifest(
		manifest.Spending{MaxPerMonthUSD: "50.00"}, nil, nil))
	if !strings.Contains(buf.String(), "max_per_month_usd is NOT enforced") {
		t.Errorf("expected a monthly-cap warning, got:\n%s", buf.String())
	}
}

func TestWarnPricingWithoutLimits(t *testing.T) {
	buf := withCapturedSpendingWarn(t)
	warnUnenforcedSpending(spendingManifest(
		manifest.Spending{}, []manifest.MCPServer{pricedServer}, nil))
	if !strings.Contains(buf.String(), "no spending limits") {
		t.Errorf("expected a pricing-without-limits warning, got:\n%s", buf.String())
	}
}

// TestNoWarningWhenFullyEnforced: a clean configuration must stay quiet.
func TestNoWarningWhenFullyEnforced(t *testing.T) {
	buf := withCapturedSpendingWarn(t)
	warnUnenforcedSpending(spendingManifest(
		manifest.Spending{MaxPerRunUSD: "0.50"},
		[]manifest.MCPServer{pricedServer},
		nil,
	))
	if buf.Len() != 0 {
		t.Errorf("unexpected warning for a fully enforced config:\n%s", buf.String())
	}
}
