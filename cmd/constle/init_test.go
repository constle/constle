package main

import (
	"strings"
	"testing"

	"github.com/constle/constle/pkg/manifest"
)

// TestDefaultAgentYAMLParsesStrictly: `constle init` writes this file and then
// tells the operator to run `constle validate` on it. Now that decoding is
// strict, a single typo in the template — or a field renamed in the schema
// without the template following — would make the first command a new user
// runs reject the file the previous command just wrote.
//
// This asserts parsing only, deliberately. The template does not currently
// pass Validate: it declares spending.max_per_day_usd with no identity.did,
// which validateSpending requires, so `constle init && constle validate
// agent.yaml` fails out of the box. That is a separate, pre-existing defect
// in the template's content rather than its syntax, and fixing it is a choice
// between dropping the daily cap from the template and giving the template a
// DID it cannot have before `constle identity create` has run.
func TestDefaultAgentYAMLParsesStrictly(t *testing.T) {
	if _, err := manifest.Parse([]byte(defaultAgentYAML)); err != nil {
		t.Fatalf("the `constle init` template no longer parses: %v", err)
	}
}

// TestDefaultAgentYAMLArmsItsGates: the template ships human_gates.enabled:
// true deliberately. Shipping it as false — or dropping the key, which means
// the same thing — would hand every new agent a gate section that reads as
// protection and enforces nothing.
func TestDefaultAgentYAMLArmsItsGates(t *testing.T) {
	m, err := manifest.Parse([]byte(defaultAgentYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !m.HumanGates.GatesArmed() {
		t.Error("the init template must arm human gates, not declare them disabled")
	}
	if !strings.Contains(defaultAgentYAML, "enabled: true") {
		t.Error("the init template must set human_gates.enabled explicitly")
	}
}
