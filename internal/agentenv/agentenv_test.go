package agentenv

import (
	"os"
	"strings"
	"testing"

	"github.com/constle/constle/pkg/manifest"
)

// withCredentials builds a manifest declaring the given credentials.
func withCredentials(creds ...manifest.Credential) *manifest.AgentManifest {
	m := &manifest.AgentManifest{}
	m.Credentials = creds
	return m
}

// TestResolveFailsClosedOnUnsetVariable is the core of item 5: a declared
// credential the host cannot supply must stop the run, not go missing.
//
// The failure it replaces is silent in a specific and nasty way. `docker run
// -e NAME` with NAME absent from the client's environment sets nothing in the
// container AND exits 0 — no error on any path — so the agent would start,
// reach for its key, and fail somewhere inside itself with a message that says
// nothing about the Agentfile.
func TestResolveFailsClosedOnUnsetVariable(t *testing.T) {
	// Deliberately not set. t.Setenv is not used here because there is nothing
	// to set; the variable's absence is the input.
	m := withCredentials(manifest.Credential{Name: "CONSTLE_TEST_ABSENT_KEY"})
	// Reserved-prefix names are refused for a different reason, so use one that
	// is not reserved.
	m.Credentials[0].Name = "TEST_ABSENT_KEY"

	env, err := Resolve(m)
	if err == nil {
		t.Fatalf("Resolve succeeded with an unset credential and returned %v", env)
	}
	if !strings.Contains(err.Error(), "TEST_ABSENT_KEY") {
		t.Errorf("error does not name the credential: %v", err)
	}
	if !strings.Contains(err.Error(), string(ReasonUnset)) {
		t.Errorf("error does not say the variable is unset: %v", err)
	}
}

// TestResolveFailsClosedOnEmptyVariable: an empty credential is not a
// credential. Forwarding it would put the agent in exactly the state a missing
// one produces, with nothing recorded to say so.
//
// It is a separate case from unset because os.Getenv cannot tell them apart —
// it returns "" for both — and the previous implementation used Getenv, so a
// variable that was exported empty was indistinguishable from one that was
// never exported. The remedy differs too: reporting "not set" for a variable
// that is right there in the environment sends the operator to add a line that
// already exists.
func TestResolveFailsClosedOnEmptyVariable(t *testing.T) {
	t.Setenv("TEST_EMPTY_KEY", "")

	_, err := Resolve(withCredentials(manifest.Credential{Name: "TEST_EMPTY_KEY"}))
	if err == nil {
		t.Fatal("Resolve accepted a credential whose host variable is set but empty")
	}
	if !strings.Contains(err.Error(), string(ReasonEmpty)) {
		t.Errorf("error reports the wrong reason, sending the operator to the wrong fix: %v", err)
	}
}

// TestResolveNamesEveryUnresolvedCredential: stopping at the first one turns a
// single fix into a sequence of run-fix-run cycles, and each cycle is a full
// sandbox startup.
func TestResolveNamesEveryUnresolvedCredential(t *testing.T) {
	t.Setenv("TEST_PRESENT_KEY", "value")

	_, err := Resolve(withCredentials(
		manifest.Credential{Name: "TEST_MISSING_ONE"},
		manifest.Credential{Name: "TEST_PRESENT_KEY"},
		manifest.Credential{Name: "TEST_MISSING_TWO"},
	))
	if err == nil {
		t.Fatal("Resolve succeeded with two unresolvable credentials")
	}
	for _, want := range []string{"TEST_MISSING_ONE", "TEST_MISSING_TWO"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "TEST_PRESENT_KEY") {
		t.Errorf("error names a credential that resolved fine: %v", err)
	}
}

// TestResolveIndirectsThroughSecretRef is the property that makes the scoping
// per-agent rather than per-name: the value comes from the host variable named
// by secret_ref, and arrives in the sandbox under the declared name. Two agents
// can then both read ANTHROPIC_API_KEY while holding different keys.
func TestResolveIndirectsThroughSecretRef(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY_PROD", "sk-ant-prod")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-operator-default")

	env, err := Resolve(withCredentials(manifest.Credential{
		Name:      "ANTHROPIC_API_KEY",
		SecretRef: "ANTHROPIC_API_KEY_PROD",
	}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := env["ANTHROPIC_API_KEY"]; got != "sk-ant-prod" {
		t.Errorf("ANTHROPIC_API_KEY = %q, want the secret_ref's value — the indirection was ignored", got)
	}
	if len(env) != 1 {
		t.Errorf("resolved = %v, want exactly the one declared credential", env)
	}
}

// TestResolveForwardsNothingWhenNothingIsDeclared is the breaking change itself,
// pinned as a test rather than left to prose.
//
// The host here exports all three variables the previous implementation
// hardcoded. A manifest that declares no credentials must receive none of them.
func TestResolveForwardsNothingWhenNothingIsDeclared(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-operator")
	t.Setenv("GROQ_API_KEY", "gsk-operator")
	t.Setenv("AGENT_TASK", "do the thing")

	env, err := Resolve(&manifest.AgentManifest{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(env) != 0 {
		t.Errorf("resolved = %v, want empty — an undeclared credential reached the sandbox", env)
	}
}

// TestResolveGrantsOnlyWhatIsDeclared is the same property from the other side,
// and it is the finding itself: an agent that needs one of the operator's keys
// must not receive the others.
func TestResolveGrantsOnlyWhatIsDeclared(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-operator")
	t.Setenv("GROQ_API_KEY", "gsk-operator")
	t.Setenv("AGENT_TASK", "do the thing")

	env, err := Resolve(withCredentials(manifest.Credential{Name: "GROQ_API_KEY"}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := env["GROQ_API_KEY"]; got != "gsk-operator" {
		t.Errorf("GROQ_API_KEY = %q, want the host value", got)
	}
	for _, denied := range []string{"ANTHROPIC_API_KEY", "AGENT_TASK"} {
		if value, present := env[denied]; present {
			t.Errorf("%s reached an agent that never declared it (value %q present)", denied, value)
		}
	}
}

// TestResolveGrantsEveryDeclaredCredential: the map is keyed by the in-sandbox
// name, one entry per declaration.
//
// Resolve returns no ordering of its own on purpose. The audit entry's
// credentials_granted needs a deterministic order because a JSON array's order
// is part of the signed bytes, and it takes it from the manifest
// (AgentManifest.CredentialNames, covered in pkg/manifest) rather than from this
// map, which has none.
func TestResolveGrantsEveryDeclaredCredential(t *testing.T) {
	t.Setenv("ZULU_KEY", "z")
	t.Setenv("ALPHA_KEY", "a")
	t.Setenv("MIKE_KEY", "m")

	env, err := Resolve(withCredentials(
		manifest.Credential{Name: "ZULU_KEY"},
		manifest.Credential{Name: "ALPHA_KEY"},
		manifest.Credential{Name: "MIKE_KEY"},
	))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for name, want := range map[string]string{"ZULU_KEY": "z", "ALPHA_KEY": "a", "MIKE_KEY": "m"} {
		if env[name] != want {
			t.Errorf("%s = %q, want %q", name, env[name], want)
		}
	}
	if len(env) != 3 {
		t.Errorf("resolved %d variables, want 3: %v", len(env), env)
	}
}

// TestResolveRevalidatesNames covers the manifest that never went through
// Validate — a manifest built directly in Go reaches the backends without it,
// and both renderers downstream are formats a malformed name breaks out of.
// Same second line of defence buildSquidConfig keeps over ValidateAllowedHost.
func TestResolveRevalidatesNames(t *testing.T) {
	for _, tc := range []struct {
		about string
		cred  manifest.Credential
	}{
		{"shell injection in the name", manifest.Credential{Name: "KEY'; id; '"}},
		{"inline value in the docker argv", manifest.Credential{Name: "KEY=value"}},
		{"reserved gate variable", manifest.Credential{Name: "CONSTLE_A2A_URL"}},
		{"reserved proxy variable", manifest.Credential{Name: "HTTP_PROXY"}},
		{"malformed secret_ref", manifest.Credential{Name: "OK", SecretRef: "BAD NAME"}},
	} {
		t.Run(tc.about, func(t *testing.T) {
			// Set every plausible source so the refusal cannot be mistaken for
			// "the variable was missing".
			t.Setenv("HTTP_PROXY", "http://operator-proxy:8080")
			t.Setenv("CONSTLE_A2A_URL", "http://not-the-gate/")
			t.Setenv("OK", "value")

			_, err := Resolve(withCredentials(tc.cred))
			if err == nil {
				t.Fatalf("Resolve accepted %+v without Validate having run", tc.cred)
			}
			// The REASON matters, not just the refusal. An earlier version of
			// this test asserted only that an error came back, and an
			// independent review showed it stayed green with the name checks
			// deleted from Resolve: a malformed name has no host variable of
			// that spelling either, so it failed as "unavailable" instead —
			// the same outcome for this manifest, and no check at all for the
			// one whose variable does happen to exist.
			if strings.Contains(err.Error(), string(ReasonUnset)) ||
				strings.Contains(err.Error(), string(ReasonEmpty)) {
				t.Errorf("Resolve refused %+v for being unavailable rather than for its name; "+
					"the name checks are not running: %v", tc.cred, err)
			}
		})
	}
}

// TestUnresolvableIsSilentWhenEverythingResolves: the validate-time warning must
// not fire on a machine that has the keys.
func TestUnresolvableIsSilentWhenEverythingResolves(t *testing.T) {
	t.Setenv("TEST_KEY_A", "a")
	t.Setenv("TEST_KEY_B", "b")

	got := Unresolvable(withCredentials(
		manifest.Credential{Name: "TEST_KEY_A"},
		manifest.Credential{Name: "INNER_B", SecretRef: "TEST_KEY_B"},
	))
	if len(got) != 0 {
		t.Errorf("Unresolvable() = %v, want empty", got)
	}
}

// TestUnresolvedStringNamesTheHostVariable: when secret_ref is used, the
// operator has to be told which HOST variable to export — the in-sandbox name
// is not the one they need to set. When the two are the same, saying it twice
// would read as two different things.
func TestUnresolvedStringNamesTheHostVariable(t *testing.T) {
	indirect := Unresolved{Name: "ANTHROPIC_API_KEY", Source: "ANTHROPIC_API_KEY_PROD", Reason: ReasonUnset}
	if got := indirect.String(); !strings.Contains(got, "ANTHROPIC_API_KEY_PROD") {
		t.Errorf("String() = %q, want the host variable named", got)
	}

	direct := Unresolved{Name: "GROQ_API_KEY", Source: "GROQ_API_KEY", Reason: ReasonUnset}
	if got := direct.String(); strings.Count(got, "GROQ_API_KEY") != 1 {
		t.Errorf("String() = %q, want the name once when source and name agree", got)
	}
}

// TestResolveErrorsCarryNoCredentialValue: the error from Resolve reaches the
// operator's terminal and the run_failed audit entry, so a value in it is a value
// on disk and on screen.
//
// An independent review found that nothing in this package asserted it: a value
// injected into the error left every test here green. The names and the host
// variable names are deliberately in the message — those are what an operator
// needs in order to fix the run — so this pins the line between the two.
func TestResolveErrorsCarryNoCredentialValue(t *testing.T) {
	const present = "sk-ant-SECRETVALUE-present"
	t.Setenv("TEST_PRESENT_SECRET", present)
	t.Setenv("TEST_EMPTY_SECRET", "")

	// One credential resolves, one is empty, one is unset: the error is produced
	// while a resolved value is in hand, which is the state that could leak it.
	_, err := Resolve(withCredentials(
		manifest.Credential{Name: "PRESENT", SecretRef: "TEST_PRESENT_SECRET"},
		manifest.Credential{Name: "EMPTY", SecretRef: "TEST_EMPTY_SECRET"},
		manifest.Credential{Name: "MISSING", SecretRef: "TEST_MISSING_SECRET"},
	))
	if err == nil {
		t.Fatal("Resolve succeeded with an empty and an unset credential")
	}
	if strings.Contains(err.Error(), present) {
		t.Errorf("a resolved credential value is in the error, which reaches the terminal and the audit log: %v", err)
	}
	// And the message must still be actionable.
	for _, want := range []string{"EMPTY", "MISSING", "TEST_MISSING_SECRET"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error is missing %q, so an operator cannot act on it: %v", want, err)
		}
	}
}

// TestResolveReadsEachVariableOnce pins the single-pass lookup.
//
// Resolve used to classify every credential and then read the environment again
// to collect the values. An independent review reproduced a SUCCESSFUL Resolve
// carrying an empty credential by unsetting the variable between the two reads.
// Not attacker-reachable — nothing constle ships mutates its own environment
// while a run starts — but "checked, then re-read" only stays correct by
// accident.
//
// The property asserted is the one that matters rather than the call count: no
// result Resolve returns may hold a value that unresolvedIn would have refused.
func TestResolveReadsEachVariableOnce(t *testing.T) {
	t.Setenv("TEST_RACE_KEY", "value")

	looked := lookup(withCredentials(manifest.Credential{Name: "TEST_RACE_KEY"}))
	if len(looked) != 1 {
		t.Fatalf("lookup returned %d results, want 1", len(looked))
	}

	// Whatever happens to the environment now, the value already read is the one
	// that will be delivered — so the check and the delivery cannot disagree.
	if err := os.Unsetenv("TEST_RACE_KEY"); err != nil {
		t.Fatal(err)
	}
	if len(unresolvedIn(looked)) != 0 {
		t.Error("unresolvedIn consulted the live environment rather than the lookup it was given")
	}
	if looked[0].value != "value" {
		t.Errorf("the captured value is %q, want %q — Resolve would deliver something it never checked",
			looked[0].value, "value")
	}
}
