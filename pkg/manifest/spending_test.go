package manifest

import (
	"strings"
	"testing"
)

// validSpendingBase is a minimal valid manifest the spending cases mutate.
func validSpendingBase() *AgentManifest {
	m, err := Parse([]byte(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: spend-test
  version: "1.0.0"
capabilities: [read_file]
`))
	if err != nil {
		panic(err)
	}
	return m
}

func TestValidateSpendingAmounts(t *testing.T) {
	m := validSpendingBase()
	m.Spending.MaxPerRunUSD = "0.50"
	if err := m.Validate(); err != nil {
		t.Fatalf("valid per-run cap rejected: %v", err)
	}

	for field, set := range map[string]func(*AgentManifest, string){
		"max_per_run_usd":   func(m *AgentManifest, v string) { m.Spending.MaxPerRunUSD = v },
		"max_per_day_usd":   func(m *AgentManifest, v string) { m.Spending.MaxPerDayUSD = v },
		"max_per_month_usd": func(m *AgentManifest, v string) { m.Spending.MaxPerMonthUSD = v },
	} {
		for _, bad := range []string{"abc", "-1", "1e3", "0.000000001", "0", "0.00"} {
			m := validSpendingBase()
			m.Identity.DID = testDID(t, 1) // so the day-cap DID rule doesn't mask the amount error
			set(m, bad)
			if err := m.Validate(); err == nil {
				t.Errorf("%s=%q: want validation error", field, bad)
			}
		}
	}
}

// TestValidateDailyCapRequiresDID: durable daily tracking is keyed by DID —
// declaring a daily cap without one must fail closed at validation.
func TestValidateDailyCapRequiresDID(t *testing.T) {
	m := validSpendingBase()
	m.Spending.MaxPerDayUSD = "5.00"
	err := m.Validate()
	if err == nil {
		t.Fatal("daily cap without identity.did was accepted")
	}
	if !strings.Contains(err.Error(), "identity.did") {
		t.Errorf("error should point at identity.did: %v", err)
	}

	m.Identity.DID = testDID(t, 1)
	if err := m.Validate(); err != nil {
		t.Fatalf("daily cap with DID rejected: %v", err)
	}
}

func TestValidateWarnPct(t *testing.T) {
	m := validSpendingBase()
	m.Identity.DID = testDID(t, 1)
	m.Spending.MaxPerDayUSD = "5.00"
	m.Spending.Alerts.WarnAtPctOfDaily = 80
	if err := m.Validate(); err != nil {
		t.Fatalf("valid warn pct rejected: %v", err)
	}

	for _, bad := range []int{-1, 101, 1000} {
		m.Spending.Alerts.WarnAtPctOfDaily = bad
		if err := m.Validate(); err == nil {
			t.Errorf("warn_at_pct_of_daily=%d accepted", bad)
		}
	}

	// Warn threshold without a daily cap has nothing to warn about.
	m = validSpendingBase()
	m.Spending.Alerts.WarnAtPctOfDaily = 80
	if err := m.Validate(); err == nil {
		t.Error("warn_at_pct_of_daily without max_per_day_usd accepted")
	}
}

func TestValidatePricingBlocks(t *testing.T) {
	base := func() *AgentManifest {
		m := validSpendingBase()
		m.MCP.Servers = []MCPServer{{
			ID:  "llm",
			URL: "http://127.0.0.1:9/mcp",
			Pricing: &MCPPricing{Meters: []PriceMeter{
				{UsagePath: "result.usage.tokens", USDPerUnit: "0.000003"},
			}},
		}}
		return m
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("valid pricing rejected: %v", err)
	}

	m := base()
	m.MCP.Servers[0].Pricing.Meters = nil
	if err := m.Validate(); err == nil {
		t.Error("empty meters accepted")
	}

	m = base()
	m.MCP.Servers[0].Pricing.Meters[0].UsagePath = ""
	if err := m.Validate(); err == nil {
		t.Error("empty usage_path accepted")
	}

	m = base()
	m.MCP.Servers[0].Pricing.Meters[0].USDPerUnit = "not-money"
	if err := m.Validate(); err == nil {
		t.Error("unparseable usd_per_unit accepted")
	}

	// A zero per-unit price is allowed: "metered but free" is a valid,
	// explicit declaration (unlike a zero cap, which is ambiguous).
	m = base()
	m.MCP.Servers[0].Pricing.Meters[0].USDPerUnit = "0"
	if err := m.Validate(); err != nil {
		t.Errorf("zero usd_per_unit rejected: %v", err)
	}
}

func TestPricedMCPServers(t *testing.T) {
	m := validSpendingBase()
	m.MCP.Servers = []MCPServer{
		{ID: "a", URL: "http://127.0.0.1:9/mcp"},
		{ID: "b", URL: "http://127.0.0.1:9/mcp2", Pricing: &MCPPricing{Meters: []PriceMeter{
			{UsagePath: "result.n", USDPerUnit: "0.01"},
		}}},
	}
	got := m.PricedMCPServers()
	if len(got) != 1 || got[0] != "b" {
		t.Errorf("PricedMCPServers = %v, want [b]", got)
	}
}
