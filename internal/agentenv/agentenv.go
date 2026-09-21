// Package agentenv resolves the host environment variables an Agentfile
// declares under `credentials:` into the environment its sandbox receives.
//
// The package is deliberately NOT named `credentials`: .gitignore carries a
// `credentials/` rule, under "Secrets & credentials", whose job is to stop an
// operator's credential directory from ever being committed. A source directory
// of that name is silently excluded by it — this package was, on its first
// commit, and every local test stayed green because they ran against the working
// tree rather than against what the commit contained. Punching a negation
// through a secrets rule to reclaim the name would weaken the rule for every
// file added to that directory afterwards, so the package moved instead.
//
// It is the only place in constle that reads the host environment on an
// agent's behalf. Before this package existed the backends forwarded a
// hardcoded set of names — ANTHROPIC_API_KEY, GROQ_API_KEY and AGENT_TASK —
// into every sandbox whenever they were set on the host, so an agent that
// needed one of the operator's keys received all of them. The set was
// operator-wide; nothing about it was per-agent.
//
// Two honest limits on what this achieves. The constle process is started from
// the operator's shell and inherits its environment, and no Go program can
// unsee its own: the Docker backend deliberately passes that inherited
// environment on to the `docker` client, which needs DOCKER_HOST, PATH and
// HOME to reach the daemon at all. That client is a host-side child process,
// not the sandbox. And the sandbox's environment is not only what this package
// returns — the image's own ENV and the variables a container runtime supplies
// itself are there too. Neither is the operator's environment, which is the
// boundary this package enforces: what crosses it is the declared set and
// nothing else.
package agentenv

import (
	"fmt"
	"os"
	"strings"

	"github.com/constle/constle/pkg/manifest"
)

// Reason says why a declared credential could not be resolved.
//
// The two are kept apart because os.Getenv cannot tell them apart — it returns
// "" for both — and the fix differs: an unset variable has to be exported, a
// variable that is set and empty is usually a typo'd assignment or a secret
// store that returned nothing, and reporting that one as "not set" sends the
// operator to look at a line that is already there. (cmd/constle/style.go
// documents the same LookupEnv distinction for NO_COLOR.)
type Reason string

const (
	// ReasonUnset — the host variable does not exist.
	ReasonUnset Reason = "not set on the host"

	// ReasonEmpty — the host variable exists and holds the empty string. An
	// empty credential is not a credential: forwarding it would put the agent
	// in exactly the state a missing one produces, with nothing recorded to
	// say so.
	ReasonEmpty Reason = "set on the host but empty"
)

// Unresolved is one declared credential the host cannot supply.
type Unresolved struct {
	// Name is the credentials[].name — the variable inside the sandbox.
	Name string

	// Source is the host variable that was looked up (credentials[].secret_ref,
	// or Name when it is omitted).
	Source string

	Reason Reason
}

// String renders one entry for an operator-facing message. It names the host
// variable separately only when it differs from Name, so the common case where
// the two are the same does not read as two different things.
func (u Unresolved) String() string {
	if u.Source != u.Name {
		return fmt.Sprintf("%s (from %s: %s)", u.Name, u.Source, u.Reason)
	}
	return fmt.Sprintf("%s (%s)", u.Name, u.Reason)
}

// Resolve reads the declared credentials out of the host environment and
// returns the variables the sandbox is to receive, keyed by their in-sandbox
// name. An Agentfile that declares none yields an empty map.
//
// It fails closed, and the error names every credential that could not be
// resolved rather than the first. A declared credential that is silently
// absent is the failure mode this replaces: `docker run -e NAME` with NAME
// missing from the client's environment sets nothing in the container and
// still exits 0, so the agent would start, reach for its key, and fail
// somewhere inside itself with an error that says nothing about the manifest.
//
// Callers must resolve BEFORE creating any sandbox resource. Both backends
// call it at the top of Start for that reason: a missing key then costs
// nothing, where the same failure after network and proxy creation would have
// to unwind them.
//
// The names the run granted are recorded in the audit log from the manifest
// (AgentManifest.CredentialNames), not from this map: a JSON array's order is
// part of the signed bytes of an audit entry, and a map has no order.
func Resolve(m *manifest.AgentManifest) (map[string]string, error) {
	// Re-validate rather than trust the caller. Validate() has already
	// rejected these names for an Agentfile that came through Parse, but a
	// manifest built directly in Go reaches the backends without it, and both
	// renderers downstream — the guest env file and the docker argv — are
	// formats a malformed name breaks out of. Same second line of defence
	// buildSquidConfig keeps over ValidateAllowedHost.
	//
	// The grammar and the reserved list are re-checked here, and uniqueness is
	// not. That is the line: these two are hazards a renderer downstream cannot
	// defend itself against, while two entries differing only in case are an
	// ambiguity in the Agentfile — the map below simply takes the later one, in
	// declaration order. Validate refuses that manifest, and refusing it is a
	// policy decision that belongs there rather than here.
	for i, c := range m.Credentials {
		if err := manifest.ValidateCredentialName(c.Name); err != nil {
			return nil, fmt.Errorf("credentials[%d].name %q: %w", i, c.Name, err)
		}
		if manifest.ReservedCredentialName(c.Name) {
			return nil, fmt.Errorf("credentials[%d].name %q is reserved for constle's own run variables", i, c.Name)
		}
		if c.SecretRef != "" {
			if err := manifest.ValidateCredentialName(c.SecretRef); err != nil {
				return nil, fmt.Errorf("credentials[%d].secret_ref %q: %w", i, c.SecretRef, err)
			}
		}
	}

	// One lookup per credential, and the value that is checked is the value that
	// is delivered. An earlier version classified every credential and then read
	// the environment a second time to collect the values, which left a window
	// between the two: an independent review reproduced a successful Resolve
	// carrying an EMPTY credential by unsetting the variable in between. Nothing
	// constle ships mutates its own environment while a run starts, and neither
	// an Agentfile nor a sandbox can reach it, so it was not a live hole — but
	// "checked then re-read" is a shape that only stays safe by accident, and
	// the single pass costs nothing.
	looked := lookup(m)

	if unresolved := unresolvedIn(looked); len(unresolved) > 0 {
		return nil, fmt.Errorf(
			"%s declared in credentials but unavailable: %s — "+
				"export the variable, or point credentials[].secret_ref at the one that holds the value",
			countNoun(len(unresolved)), joinUnresolved(unresolved))
	}

	env := make(map[string]string, len(looked))
	for _, l := range looked {
		env[l.cred.Name] = l.value
	}
	return env, nil
}

// Unresolvable returns the declared credentials the host cannot supply, in
// declaration order. Empty means Resolve will succeed.
//
// It exists separately from Resolve so `constle validate` can report the same
// facts without failing: validation is not execution, and an Agentfile is
// legitimately validated on a machine that holds none of the keys — a CI
// runner, or a reviewer's laptop. The same split as identity.did, which warns
// at validate time and fails closed at run time.
//
// Both paths classify through unresolvedIn over the same lookup, so the warning
// and the refusal can never disagree about which credentials are available.
func Unresolvable(m *manifest.AgentManifest) []Unresolved {
	return unresolvedIn(lookup(m))
}

// lookedUp is one credential's single reading of the host environment.
type lookedUp struct {
	cred  manifest.Credential
	value string
	found bool
}

// lookup reads each declared credential's host variable exactly once, in
// declaration order.
func lookup(m *manifest.AgentManifest) []lookedUp {
	out := make([]lookedUp, 0, len(m.Credentials))
	for _, c := range m.Credentials {
		value, found := os.LookupEnv(c.Source())
		out = append(out, lookedUp{cred: c, value: value, found: found})
	}
	return out
}

// unresolvedIn reports which of a lookup's results the host cannot supply.
func unresolvedIn(looked []lookedUp) []Unresolved {
	var out []Unresolved
	for _, l := range looked {
		entry := Unresolved{Name: l.cred.Name, Source: l.cred.Source()}
		switch {
		case !l.found:
			entry.Reason = ReasonUnset
		case l.value == "":
			entry.Reason = ReasonEmpty
		default:
			continue
		}
		out = append(out, entry)
	}
	return out
}

// countNoun renders the subject of the Resolve error so it agrees in number.
func countNoun(n int) string {
	if n == 1 {
		return "1 credential"
	}
	return fmt.Sprintf("%d credentials", n)
}

// joinUnresolved renders the list for an error or warning message.
func joinUnresolved(list []Unresolved) string {
	parts := make([]string, len(list))
	for i, u := range list {
		parts[i] = u.String()
	}
	return strings.Join(parts, ", ")
}

// FormatUnresolvable is joinUnresolved for callers outside this package (the
// CLI's validate-time warning), so the wording of an unresolved credential is
// written once.
func FormatUnresolvable(list []Unresolved) string {
	return joinUnresolved(list)
}
