package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/identity"
	"github.com/constle/constle/pkg/manifest"
)

// identityWarnOut is where warnUnverifiableIdentity prints. Package variable
// so tests can capture the output (same pattern as gatesWarnOut).
var identityWarnOut io.Writer = os.Stdout

// cmdIdentity dispatches the `constle identity` subcommands.
func cmdIdentity(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: constle identity create|show <agent-name>")
	}

	switch args[0] {
	case "create":
		name, owner, err := parseIdentityCreateArgs(args[1:])
		if err != nil {
			return err
		}
		return cmdIdentityCreate(name, owner)

	case "show":
		if len(args) != 2 {
			return fmt.Errorf("usage: constle identity show <agent-name>")
		}
		return cmdIdentityShow(args[1])

	default:
		return fmt.Errorf("unknown identity subcommand %q\nusage: constle identity create|show <agent-name>", args[0])
	}
}

// parseIdentityCreateArgs extracts the agent name and the optional --owner
// flag from `constle identity create` arguments.
func parseIdentityCreateArgs(args []string) (name, owner string, err error) {
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--owner="):
			owner = strings.TrimPrefix(arg, "--owner=")
		case strings.HasPrefix(arg, "-"):
			return "", "", fmt.Errorf("unknown flag %q\nusage: constle identity create [--owner=<email>] <agent-name>", arg)
		case name == "":
			name = arg
		default:
			return "", "", fmt.Errorf("unexpected argument %q", arg)
		}
	}
	if name == "" {
		return "", "", fmt.Errorf("usage: constle identity create [--owner=<email>] <agent-name>")
	}
	return name, owner, nil
}

func cmdIdentityCreate(name, owner string) error {
	id, err := identity.Create(name, owner)
	if err != nil {
		return err
	}

	printf("\n✓ identity created for agent %q\n\n", name)
	printf("  did:       %s\n", id.DID())
	if owner != "" {
		printf("  owner:     %s\n", owner)
	}
	printf("  key file:  %s (mode 0600 — never leaves this machine)\n", identity.Dir(name))
	printf("\n")
	printf("  add the DID (and only the DID) to your Agentfile:\n\n")
	printf("    identity:\n")
	printf("      name: %s\n", name)
	printf("      did: %s\n", id.DID())
	printf("\n")
	return nil
}

func cmdIdentityShow(name string) error {
	id, err := identity.Load(name)
	if err != nil {
		return err
	}

	printf("\n  agent:     %s\n", name)
	printf("  did:       %s\n", id.DID())
	if id.Owner != "" {
		printf("  owner:     %s\n", id.Owner)
	}
	if !id.CreatedAt.IsZero() {
		printf("  created:   %s\n", id.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
	}
	printf("  key file:  %s\n\n", identity.Dir(name))
	return nil
}

// loadRunIdentity resolves the identity declared by identity.did for a run,
// failing closed on every path that would make the declared identity a lie:
// no local key, a key that derives a different DID than the Agentfile
// declares, or an owner conflict. `constle run` must refuse to run rather
// than proceed unsigned.
func loadRunIdentity(m *manifest.AgentManifest) (*identity.Identity, error) {
	id, err := identity.Load(m.Identity.Name)
	if err != nil {
		if _, ok := err.(*identity.NotFoundError); ok {
			return nil, fmt.Errorf(
				"Agentfile declares identity.did but no local identity exists for agent %q — "+
					"refusing to run unsigned; create one with: constle identity create %s",
				m.Identity.Name, m.Identity.Name,
			)
		}
		return nil, fmt.Errorf("Agentfile declares identity.did but the local identity cannot be used: %w", err)
	}

	if id.DID() != m.Identity.DID {
		return nil, fmt.Errorf(
			"identity mismatch: Agentfile declares %s but the local key for agent %q derives %s — "+
				"refusing to run; fix identity.did in the Agentfile or recreate the identity",
			m.Identity.DID, m.Identity.Name, id.DID(),
		)
	}

	if m.Identity.Owner != "" && id.Owner != "" && id.Owner != m.Identity.Owner {
		return nil, fmt.Errorf(
			"identity owner mismatch: Agentfile declares owner %q but the local identity for agent %q is bound to %q",
			m.Identity.Owner, m.Identity.Name, id.Owner,
		)
	}

	return id, nil
}

// warnUnverifiableIdentity warns at validate time when identity.did is
// declared but the audit log cannot actually be signed on this machine.
// Same principle as warnUnenforcedHumanGates: a declared protection must
// never look real when it isn't. `constle validate` warns; `constle run`
// fails closed.
func warnUnverifiableIdentity(m *manifest.AgentManifest) {
	if m.Identity.DID == "" {
		return
	}
	if _, err := loadRunIdentity(m); err == nil {
		return
	}

	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	fmt.Fprintln(identityWarnOut, "⚠️  warning: identity.did is declared but NOT usable on this machine:")
	fmt.Fprintf(identityWarnOut, "   no matching local private key for agent %q — audit log signing would\n", m.Identity.Name)
	fmt.Fprintln(identityWarnOut, "   silently be a lie, so 'constle run' will refuse to start this agent here.")
	fmt.Fprintf(identityWarnOut, "   create the identity with: constle identity create %s\n", m.Identity.Name)
	fmt.Fprintln(identityWarnOut)
}

// cmdAuditVerify implements `constle audit verify <logfile>`: it checks every
// signature against the public key recovered directly from the DID inside
// the log (no external service) and walks the hash chain, reporting the
// exact line and kind of tampering on failure.
func cmdAuditVerify(path, expectedDID string) error {
	report, err := audit.VerifyFile(path, expectedDID)
	if err != nil {
		if te, ok := err.(*audit.TamperError); ok {
			return fmt.Errorf("TAMPERING DETECTED in %s\n  %v", path, te)
		}
		return err
	}

	printf("\n✓ audit log verified: %s\n\n", path)
	printf("  entries:   %d (all signatures valid, hash chain intact)\n", report.Entries)
	printf("  signed by: %s\n", report.DID)
	if expectedDID != "" {
		printf("  pinned:    DID matches the expected identity\n")
	}
	printf("\n")
	return nil
}

// parseAuditVerifyArgs extracts the log path and the optional --did flag
// from `constle audit verify` arguments.
func parseAuditVerifyArgs(args []string) (path, expectedDID string, err error) {
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--did="):
			expectedDID = strings.TrimPrefix(arg, "--did=")
		case strings.HasPrefix(arg, "-"):
			return "", "", fmt.Errorf("unknown flag %q\nusage: constle audit verify [--did=<did:key:…>] <logfile>", arg)
		case path == "":
			path = arg
		default:
			return "", "", fmt.Errorf("unexpected argument %q", arg)
		}
	}
	if path == "" {
		return "", "", fmt.Errorf("usage: constle audit verify [--did=<did:key:…>] <logfile>")
	}
	return path, expectedDID, nil
}
