package manifest

import (
	"fmt"
	"strings"
)

// reservedCredentialNames are the variable names constle builds for a run
// itself. A credential may not claim one.
//
// Two groups, for two different reasons:
//
//   - The proxy variables. HTTP_PROXY, HTTPS_PROXY and their lowercase twins
//     carry the address of the per-run Squid proxy, which is how the agent
//     reaches anything at all. ALL_PROXY and FTP_PROXY carry it too: clients
//     honour ALL_PROXY as the fallback for every scheme, and the Docker CLI
//     fills both in from the operator's ~/.docker/config.json when constle does
//     not — a value that is a URL, and so can carry the operator's proxy
//     password. NO_PROXY is the exemption list, which is the gate address on
//     Firecracker and empty on Docker.
//
//     Every name here is one the runtime WRITES on every run. That is load
//     bearing: a name reserved in this validator but never written would leave
//     the backends' composition ordering with nothing to overwrite, so the
//     second, validation-independent guard would not exist for it.
//
//   - The CONSTLE_ prefix. These are minted per run — the MCP and A2A gate
//     URLs, which carry that run's gate token, and the Firecracker guest's
//     network parameters. A prefix rather than a list, so an infrastructure
//     variable added later is protected from the moment it exists rather than
//     when somebody remembers to extend a list here.
//
// Matching is case-insensitive, and that is a correctness requirement rather
// than caution: constle is built for Windows as well as unix, and Windows
// environment variables are case-insensitive, so `http_proxy` and `HTTP_PROXY`
// are one variable there and two on Linux. A case-sensitive rule would make
// whether an Agentfile can overwrite its own sandbox's proxy address a
// property of the host OS.
var reservedCredentialNames = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "ALL_PROXY", "NO_PROXY",
}

// reservedCredentialPrefix is reserved in full — see reservedCredentialNames.
const reservedCredentialPrefix = "CONSTLE_"

// ValidateCredentialName checks one credentials[].name against the grammar
// both backends can render safely. It returns the reason a name is refused,
// without the field path; callers add that.
//
// The rule is POSIX's portable environment-variable name — an initial letter
// or underscore, then letters, digits and underscores — and it is narrow for
// the same reason ValidateAllowedHost is: the name is rendered into two
// formats that have no escaping for it.
//
//   - The Firecracker backend writes each variable into the guest's env file
//     as `export NAME='value'` (buildWorkspaceImage). The value is quoted;
//     the name cannot be, because a quoted name is not an assignment. A name
//     containing a quote, a semicolon or a newline therefore closes the
//     statement and starts another one, inside a file the guest sources as
//     root before the agent runs.
//   - The Docker backend passes each variable as `docker run -e NAME`, with no
//     "=", precisely so the value is resolved from the client's own
//     environment instead of appearing in a world-readable argv (see
//     agentRunArgs). A name containing "=" turns that back into an inline
//     `-e NAME=VALUE` and undoes it.
//
// There is no way to render an arbitrary string into either format safely, so
// the string must not be arbitrary. Both failures are refused here rather than
// escaped downstream, because an escaping bug in either renderer is silent.
//
// credentials.Resolve calls this again before it resolves anything, so a
// manifest constructed in Go without Validate cannot skip it — the same
// second line of defence buildSquidConfig keeps over ValidateAllowedHost.
func ValidateCredentialName(name string) error {
	if name == "" {
		return fmt.Errorf("must not be empty")
	}
	for i, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return fmt.Errorf("must not start with a digit")
			}
		default:
			return fmt.Errorf("contains %q (only letters, digits, and underscores are allowed)", r)
		}
	}
	return nil
}

// ReservedCredentialNames returns the exact proxy names reserved by name, as
// opposed to by the CONSTLE_ prefix.
//
// Exported for the backends' own tests, which assert the invariant neither
// package can check alone: this set and the set of proxy variables the backends
// WRITE must be equal. A name reserved here but written by no backend has no
// structural guard — only this validator stands between a manifest and the
// sandbox's egress path, which is what an independent review found for
// ALL_PROXY, FTP_PROXY, and NO_PROXY on a run with no gate bound. A name written
// by a backend but missing here can be declared as a credential, and the backend
// then silently overrides it: the operator's variable vanishes with no error.
//
// Returns a copy, so a caller cannot edit the policy it is checking.
func ReservedCredentialNames() []string {
	out := make([]string, len(reservedCredentialNames))
	copy(out, reservedCredentialNames)
	return out
}

// ReservedCredentialName reports whether name is one constle builds for the
// run itself, and must therefore not be claimed by a credential.
func ReservedCredentialName(name string) bool {
	upper := strings.ToUpper(name)
	if strings.HasPrefix(upper, reservedCredentialPrefix) {
		return true
	}
	for _, reserved := range reservedCredentialNames {
		if upper == reserved {
			return true
		}
	}
	return false
}

// validateCredentials refuses a credentials section that could not be
// delivered as written.
//
// Every rule here is an error rather than a warning, because each one covers a
// case where the declaration would otherwise be silently wrong rather than
// visibly broken: a malformed name is a rendering hazard in the backends, a
// reserved name overwrites the run's own infrastructure, and a duplicate name
// means two entries resolve to one variable with no rule saying which wins.
//
// What is NOT checked here is whether the host actually holds the value: that
// depends on the machine, and `constle validate` legitimately runs on one that
// has no keys (a CI runner). It is checked at run time instead, where it fails
// closed before any sandbox resource is created — the same split identity.did
// uses (spec/agent-manifest.md §5.4).
func (m *AgentManifest) validateCredentials() error {
	// Keyed by the UPPERCASED name, so a case variant counts as the same
	// variable. Windows environment variables are case-insensitive, so FOO and
	// foo are one variable there and two on unix — exactly the reasoning
	// ReservedCredentialName is case-insensitive for, applied to the other check
	// that asks "is this the same variable". Without it, `FOO` beside `foo`
	// validates, and which value the agent receives on Windows is decided by
	// whatever the environment layer does with the pair.
	type declared struct {
		index int
		name  string
	}
	seen := make(map[string]declared, len(m.Credentials))

	for i, c := range m.Credentials {
		if err := ValidateCredentialName(c.Name); err != nil {
			return fmt.Errorf(
				"credentials[%d].name: invalid name %q — %w; "+
					"use an environment variable name such as ANTHROPIC_API_KEY",
				i, c.Name, err)
		}

		if ReservedCredentialName(c.Name) {
			return fmt.Errorf(
				"credentials[%d].name: %q is reserved — constle builds it for the run itself "+
					"(the %s* gate and guest variables, and the HTTP_PROXY/HTTPS_PROXY/"+
					"ALL_PROXY/FTP_PROXY/NO_PROXY proxy address); declaring it would point the agent's "+
					"own sandbox somewhere else. Forward the value under a different name",
				i, c.Name, reservedCredentialPrefix)
		}

		// Duplicate names are rejected rather than deduplicated: the two
		// entries may name different host variables, and then "which value the
		// agent gets" is decided by iteration order rather than by the
		// Agentfile. Naming the earlier index makes the pair findable in a long
		// list.
		if first, dup := seen[strings.ToUpper(c.Name)]; dup {
			// A pair differing only in case gets its own sentence. Told that
			// "foo is already declared" when the earlier entry reads FOO, an
			// author looks for a third entry that is not there.
			if first.name != c.Name {
				return fmt.Errorf(
					"credentials[%d].name: %q differs from %q at credentials[%d] only in case — "+
						"environment variable names are case-insensitive on Windows, so these are "+
						"one variable there and two here; pick one spelling",
					i, c.Name, first.name, first.index)
			}
			return fmt.Errorf(
				"credentials[%d].name: %q is already declared at credentials[%d] — "+
					"one variable cannot carry two values",
				i, c.Name, first.index)
		}
		seen[strings.ToUpper(c.Name)] = declared{index: i, name: c.Name}

		// secret_ref is held to the name grammar (it is looked up in the host
		// environment, where the same grammar applies) but NOT to the reserved
		// list: it names a variable the operator owns, and forwarding the
		// operator's own HTTP_PROXY into the sandbox under some other name is
		// their business.
		if c.SecretRef != "" {
			if err := ValidateCredentialName(c.SecretRef); err != nil {
				return fmt.Errorf(
					"credentials[%d].secret_ref: invalid name %q — %w; "+
						"it names the host environment variable holding the value",
					i, c.SecretRef, err)
			}
		}
	}

	return nil
}

// CredentialNames returns the declared credential names, in declaration order.
// Used for the run summary and the run_started audit entry — names only, never
// values.
func (m *AgentManifest) CredentialNames() []string {
	names := make([]string, len(m.Credentials))
	for i, c := range m.Credentials {
		names[i] = c.Name
	}
	return names
}
