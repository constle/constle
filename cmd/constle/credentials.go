package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/constle/constle/internal/agentenv"
	"github.com/constle/constle/internal/termsafe"
	"github.com/constle/constle/pkg/manifest"
)

// credentialsWarnOut is where warnUnresolvableCredentials prints. Package
// variable so tests can capture the output (same pattern as gatesWarnOut).
var credentialsWarnOut io.Writer = os.Stdout

// credentialsSummary renders the credentials row of the run and validate
// summaries.
//
// The row is printed unconditionally, including when nothing is declared, and
// that is the whole point of it. An Agentfile that declares no credentials
// receives none — where a previous version forwarded the operator's
// ANTHROPIC_API_KEY, GROQ_API_KEY and AGENT_TASK to every agent that ran. The
// visible symptom of the change is an agent reaching for a key it no longer
// has and failing somewhere inside itself, so the summary says so up front
// rather than leaving the operator to infer it from the container's output.
//
// Deliberately not derived from the host: scanning the environment for
// key-shaped names the manifest forgot to declare would print which secrets
// the operator holds, in order to guess at intent, and would make the output
// depend on the machine it ran on.
//
// The names go through termsafe.Line even though ValidateCredentialName already
// admits no escape byte — for the same reason every other Agentfile-derived
// string in these summaries does. The grammar is the reason this is safe today;
// relying on it here would make relaxing that grammar later a terminal-control
// bug in a file nobody would think to look at, and the escaping costs a call.
func credentialsSummary(m *manifest.AgentManifest) string {
	if len(m.Credentials) == 0 {
		return "none declared — no host variables are forwarded"
	}
	return termsafe.Line(strings.Join(m.CredentialNames(), ", "))
}

// credentialsSummaryStyled is credentialsSummary for the TTY rows: the names
// in the value colour, or the empty case in the muted qualifier colour, since
// "none declared" is a statement about the manifest rather than a value read
// out of it.
func credentialsSummaryStyled(m *manifest.AgentManifest) string {
	initStyles()
	if len(m.Credentials) == 0 {
		return stMuted.Render("none declared  ∙  no host variables forwarded")
	}
	return stInk.Render(termsafe.Line(strings.Join(m.CredentialNames(), ", ")))
}

// warnUnresolvableCredentials warns at validate time about declared
// credentials the host cannot supply.
//
// Same split as warnUnverifiableIdentity, for the same reason: `constle
// validate` warns and `constle run` fails closed. Validation is not execution,
// and an Agentfile is legitimately validated where none of the keys exist — a
// CI runner, or a reviewer's machine. Failing there would make the check
// useless precisely where it is most used; staying silent would let an
// Agentfile that cannot run report clean.
func warnUnresolvableCredentials(m *manifest.AgentManifest) {
	unresolved := agentenv.Unresolvable(m)
	if len(unresolved) == 0 {
		return
	}

	lines := []string{
		"⚠️  warning: some declared credentials are not available on this machine:",
		fmt.Sprintf("   %s", termsafe.Line(agentenv.FormatUnresolvable(unresolved))),
		"   `constle run` will refuse to start until each one resolves —",
		"   export the variable, or point credentials[].secret_ref at the one that holds it",
	}

	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	warnBlock(credentialsWarnOut, lines)
}
