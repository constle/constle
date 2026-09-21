package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/constle/constle/internal/sandbox"
	"github.com/constle/constle/pkg/manifest"
)

// withCapturedCredentialsWarn redirects warnUnresolvableCredentials output into
// a buffer for one test (same pattern as withCapturedGatesWarn).
func withCapturedCredentialsWarn(t *testing.T) *bytes.Buffer {
	t.Helper()

	orig := credentialsWarnOut
	t.Cleanup(func() { credentialsWarnOut = orig })

	buf := &bytes.Buffer{}
	credentialsWarnOut = buf
	return buf
}

// credentialsManifest builds an in-memory manifest declaring creds.
func credentialsManifest(creds ...manifest.Credential) *manifest.AgentManifest {
	return &manifest.AgentManifest{
		APIVersion:  "constle.dev/v1alpha1",
		Kind:        "AgentManifest",
		Identity:    manifest.Identity{Name: "credentials-test"},
		Credentials: creds,
	}
}

// TestCredentialsSummaryStatesTheEmptyCase is the mitigation for the one bad
// property of the breaking change: an agent that used to be handed the
// operator's keys now gets nothing, and the way that failure shows up on its own
// is an opaque error from inside the container.
//
// So the row is printed even when there is nothing to print, and it says what
// the silence means. A summary that simply omitted the row would leave the
// operator to infer the change from a stack trace in someone else's code.
func TestCredentialsSummaryStatesTheEmptyCase(t *testing.T) {
	got := credentialsSummary(credentialsManifest())
	if got == "" {
		t.Fatal("credentialsSummary returned nothing for a manifest with no credentials; the row would vanish")
	}
	for _, want := range []string{"none declared", "forwarded"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q does not say %q — it has to state that nothing is forwarded, not just that nothing is declared", got, want)
		}
	}
}

// TestCredentialsSummaryListsDeclaredNames: names, in declaration order, and
// nothing that could be a value.
func TestCredentialsSummaryListsDeclaredNames(t *testing.T) {
	got := credentialsSummary(credentialsManifest(
		manifest.Credential{Name: "GROQ_API_KEY"},
		manifest.Credential{Name: "AGENT_TASK"},
	))
	if got != "GROQ_API_KEY, AGENT_TASK" {
		t.Errorf("credentialsSummary = %q, want the declared names in order", got)
	}
}

// TestCredentialsSummaryNeverShowsTheHostVariable pins a small but real
// confidentiality choice: secret_ref names a variable in the operator's own
// environment, and the summary is the sort of output that ends up pasted into
// an issue. The in-sandbox name is what the Agentfile is about; the host
// layout is not.
func TestCredentialsSummaryNeverShowsTheHostVariable(t *testing.T) {
	got := credentialsSummary(credentialsManifest(
		manifest.Credential{Name: "ANTHROPIC_API_KEY", SecretRef: "ANTHROPIC_API_KEY_PROD_TEAM_7"},
	))
	if strings.Contains(got, "ANTHROPIC_API_KEY_PROD_TEAM_7") {
		t.Errorf("summary %q exposes the operator's host variable layout", got)
	}
	if !strings.Contains(got, "ANTHROPIC_API_KEY") {
		t.Errorf("summary %q does not name the credential", got)
	}
}

// TestCredentialsSummaryEscapesTerminalControl is defence in depth rather than
// a live exploit: ValidateCredentialName admits no escape byte, so a manifest
// that reached these summaries through Parse and Validate cannot carry one.
//
// It is asserted anyway because the safety currently rests on a charset rule in
// another package, and the summaries do not say so. Relaxing that grammar later
// — to allow a dot, say — would turn this row into a terminal-control primitive
// with nothing in this file to notice. Constle prints the human gate's question
// on stdout and reads the answer on stdin, which is what made that class of bug
// worth a release of its own (#54).
func TestCredentialsSummaryEscapesTerminalControl(t *testing.T) {
	m := credentialsManifest(manifest.Credential{Name: "KEY\x1b[2J\x1b[H"})
	for label, got := range map[string]string{
		"credentialsSummary": credentialsSummary(m),
		"warning":            warnCredentialsOutput(t, m),
	} {
		if strings.ContainsRune(got, 0x1b) {
			t.Errorf("%s passed an ESC byte through to the terminal: %q", label, got)
		}
	}
}

// warnCredentialsOutput captures one warnUnresolvableCredentials call.
func warnCredentialsOutput(t *testing.T, m *manifest.AgentManifest) string {
	t.Helper()
	buf := withCapturedCredentialsWarn(t)
	warnUnresolvableCredentials(m)
	return buf.String()
}

// TestWarnUnresolvableCredentials: validate warns, and the warning has to carry
// the one thing the operator needs — which HOST variable to export. With
// secret_ref in play that is not the same string as the credential's name.
func TestWarnUnresolvableCredentials(t *testing.T) {
	t.Run("warns and names the host variable", func(t *testing.T) {
		buf := withCapturedCredentialsWarn(t)
		warnUnresolvableCredentials(credentialsManifest(
			manifest.Credential{Name: "ANTHROPIC_API_KEY", SecretRef: "TEST_UNSET_PROD_KEY"},
		))
		out := buf.String()
		if out == "" {
			t.Fatal("no warning for a credential this machine cannot supply")
		}
		if !strings.Contains(out, "TEST_UNSET_PROD_KEY") {
			t.Errorf("warning does not name the host variable to export:\n%s", out)
		}
		if !strings.Contains(out, "constle run") {
			t.Errorf("warning does not say that run will refuse to start, so it reads as advisory:\n%s", out)
		}
	})

	t.Run("silent when everything resolves", func(t *testing.T) {
		t.Setenv("TEST_PRESENT_CRED", "value")
		buf := withCapturedCredentialsWarn(t)
		warnUnresolvableCredentials(credentialsManifest(manifest.Credential{Name: "TEST_PRESENT_CRED"}))
		if out := buf.String(); out != "" {
			t.Errorf("warned about a credential that resolves:\n%s", out)
		}
	})

	t.Run("silent when nothing is declared", func(t *testing.T) {
		buf := withCapturedCredentialsWarn(t)
		warnUnresolvableCredentials(credentialsManifest())
		if out := buf.String(); out != "" {
			t.Errorf("warned about an empty credentials section:\n%s", out)
		}
	})
}

// TestRunStartedDetailsRecordsGrantedCredentials is the audit half of the
// finding. "Which of the operator's keys did this agent hold" has to be
// answerable after the fact, from the signed log, rather than inferred from
// which keys the operator happened to have exported that day.
func TestRunStartedDetailsRecordsGrantedCredentials(t *testing.T) {
	sel := &sandbox.Selection{
		Type:      sandbox.BackendDocker,
		Requested: manifest.IsolationNetwork,
		Achieved:  manifest.IsolationNetwork,
	}

	t.Run("names in declaration order", func(t *testing.T) {
		m := credentialsManifest(
			manifest.Credential{Name: "ZULU_KEY"},
			manifest.Credential{Name: "ALPHA_KEY"},
		)
		got, ok := runStartedDetails(m, sel)["credentials_granted"].([]string)
		if !ok {
			t.Fatalf("credentials_granted is not a []string: %#v", runStartedDetails(m, sel)["credentials_granted"])
		}
		if len(got) != 2 || got[0] != "ZULU_KEY" || got[1] != "ALPHA_KEY" {
			t.Errorf("credentials_granted = %v, want declaration order [ZULU_KEY ALPHA_KEY]", got)
		}
	})

	t.Run("present and empty when nothing was granted", func(t *testing.T) {
		details := runStartedDetails(credentialsManifest(), sel)
		got, present := details["credentials_granted"]
		if !present {
			t.Fatal("credentials_granted is absent; \"this agent was granted nothing\" must be a recorded fact, not the absence of one")
		}
		if names, ok := got.([]string); !ok || len(names) != 0 {
			t.Errorf("credentials_granted = %#v, want an empty []string", got)
		}
	})

	t.Run("carries no values", func(t *testing.T) {
		const secret = "sk-ant-SECRETVALUE-must-not-be-logged"
		t.Setenv("TEST_AUDIT_KEY", secret)

		m := credentialsManifest(manifest.Credential{Name: "TEST_AUDIT_KEY"})
		// Marshalled, because that is what reaches the log file: an assertion
		// over the map alone would miss a value smuggled in under any other key.
		encoded, err := json.Marshal(runStartedDetails(m, sel))
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if strings.Contains(string(encoded), secret) {
			t.Errorf("a credential value reached the audit entry:\n%s", encoded)
		}
		if !strings.Contains(string(encoded), "TEST_AUDIT_KEY") {
			t.Errorf("the credential name is missing from the audit entry:\n%s", encoded)
		}
	})
}
