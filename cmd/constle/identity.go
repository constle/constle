package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/humangate"
	"github.com/constle/constle/internal/identity"
	"github.com/constle/constle/internal/termsafe"
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
		printf("  owner:     %s\n", termsafe.Line(owner))
	}
	printf("  key file:  %s (mode 0600 — never leaves this machine)\n", termsafe.Line(identity.Dir(name)))
	printf("\n")
	printf("  add the DID (and only the DID) to your Agentfile:\n\n")
	printf("    identity:\n")
	printf("      name: %s\n", termsafe.Line(name))
	printf("      did: %s\n", id.DID())
	printf("\n")
	return nil
}

func cmdIdentityShow(name string) error {
	id, err := identity.Load(name)
	if err != nil {
		return err
	}

	printf("\n  agent:     %s\n", termsafe.Line(name))
	printf("  did:       %s\n", id.DID())
	if id.Owner != "" {
		printf("  owner:     %s\n", termsafe.Line(id.Owner))
	}
	if !id.CreatedAt.IsZero() {
		printf("  created:   %s\n", id.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
	}
	printf("  key file:  %s\n\n", termsafe.Line(identity.Dir(name)))
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
				"the Agentfile declares identity.did but no local identity exists for agent %q — "+
					"refusing to run unsigned; create one with: constle identity create %q",
				m.Identity.Name, m.Identity.Name,
			)
		}
		return nil, fmt.Errorf("the Agentfile declares identity.did but the local identity cannot be used: %w", err)
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

	lines := []string{
		"⚠️  warning: identity.did is declared but NOT usable on this machine:",
		fmt.Sprintf("   no matching local private key for agent %q — audit log signing would", m.Identity.Name),
		"   silently be a lie, so 'constle run' will refuse to start this agent here.",
		fmt.Sprintf("   create the identity with: constle identity create %s", m.Identity.Name),
	}

	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	warnBlock(identityWarnOut, lines)
}

// cmdAuditVerify implements `constle audit verify <logfile>`: it checks every
// signature against the public key recovered directly from the DID inside
// the log (no external service) and walks the hash chain, reporting the
// exact line and kind of tampering on failure.
//
// It then re-verifies the human-gate decisions the log records (spec
// human-gates-webhook.md §9). The two checks answer different questions and
// neither substitutes for the other: the chain proves the runtime's own
// account of a run has not been altered since it was written, while the
// decision check asks whether the approver's signature actually supports
// what that account claims. A log can be perfectly intact and still record
// an approval nobody signed.
func cmdAuditVerify(a auditVerifyArgs) error {
	path := a.path
	expectedDID, approverPubkey, err := a.resolvePins()
	if err != nil {
		return err
	}

	report, err := audit.VerifyFile(path, expectedDID)
	if err != nil {
		if te, ok := err.(*audit.TamperError); ok {
			// te's detail is already bounded and quoted by internal/audit;
			// path is whatever the operator typed on the command line.
			return fmt.Errorf("TAMPERING DETECTED in %s\n  %v", termsafe.Line(path), te)
		}
		return err
	}

	decisions, err := humangate.VerifyDecisions(report.Parsed, approverPubkey)
	if err != nil {
		return err
	}

	printf("\n✓ audit log verified: %s\n\n", termsafe.Line(path))
	printf("  entries:   %d (all signatures valid, hash chain intact)\n", report.Entries)
	// report.DID reached here through did.PublicKey, so it is already a
	// did:key charset. Escaped anyway: a reader should not have to trace that
	// to see the line is safe, and the guarantee is the verifier's to change.
	printf("  signed by: %s\n", termsafe.Line(report.DID))
	if expectedDID != "" {
		printf("  pinned:    DID matches the expected identity\n")
	}
	if a.agentfile != "" {
		printf("  pins from: %s (%s)\n", a.agentfile, describePins(expectedDID, approverPubkey))
	}
	printf("\n")

	reportGateDecisions(decisions, approverPubkey)
	if !decisions.OK() {
		return fmt.Errorf("%d human-gate decision(s) in %s do not hold up — see above",
			len(decisions.Failures), path)
	}
	return nil
}

// reportGateDecisions prints the §9 decision check. It stays silent for a
// log with no gate decisions in it, rather than printing a row of zeros for
// every run that never gated a call.
func reportGateDecisions(d *humangate.DecisionReport, approverPubkey string) {
	if d.Verified == 0 && d.Unanswered == 0 && len(d.Unproven) == 0 && len(d.Failures) == 0 {
		return
	}

	printf("  human gates (webhook decisions, spec §9):\n")
	if d.Verified > 0 {
		printf("    ✓ %d decision(s) re-verified against the approver's key\n", d.Verified)
	}
	if d.Unanswered > 0 {
		printf("    · %d gate(s) opened but never answered (nothing signed to verify)\n", d.Unanswered)
	}
	if approverPubkey == "" && d.Verified > 0 {
		printf("    · verified against each entry's own recorded approver_pubkey; pass\n")
		printf("      --approver-pubkey=<did:key:…> from the Agentfile to pin the key\n")
	}
	for _, p := range d.Unproven {
		printf("    ? %s\n", p)
	}
	if len(d.Unproven) > 0 {
		printf("      (this log records no signed decisions at all — expected for a log\n")
		printf("       written before spec 0.4.0, which did not persist them)\n")
	}
	for _, p := range d.Failures {
		printf("    ✗ %s\n", p)
	}
	printf("\n")
}

// auditVerifyArgs is one invocation of `constle audit verify`: the log to
// check, and the trust anchors to hold it to.
//
// The two anchors answer different questions — did is the agent identity the
// log must be signed with, approverPubkey is the
// human_gates.approver_pubkey its recorded gate decisions must verify
// against — but both are declared in the same Agentfile, so agentfile
// supplies either or both rather than making an operator paste two did:key
// strings by hand to check one log.
type auditVerifyArgs struct {
	path           string
	did            string
	approverPubkey string
	agentfile      string
}

// parseAuditVerifyArgs extracts the log path and the optional flags. It
// touches no files: resolving the Agentfile is resolvePins's job, so the
// parsing can be tested without one.
func parseAuditVerifyArgs(args []string) (auditVerifyArgs, error) {
	var a auditVerifyArgs
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--did="):
			a.did = strings.TrimPrefix(arg, "--did=")
		case strings.HasPrefix(arg, "--approver-pubkey="):
			a.approverPubkey = strings.TrimPrefix(arg, "--approver-pubkey=")
		case strings.HasPrefix(arg, "--agentfile="):
			a.agentfile = strings.TrimPrefix(arg, "--agentfile=")
		case strings.HasPrefix(arg, "-"):
			return auditVerifyArgs{}, fmt.Errorf("unknown flag %q\n%s", arg, auditVerifyUsage)
		case a.path == "":
			a.path = arg
		default:
			return auditVerifyArgs{}, fmt.Errorf("unexpected argument %q", arg)
		}
	}
	if a.path == "" {
		return auditVerifyArgs{}, fmt.Errorf("%s", auditVerifyUsage)
	}
	return a, nil
}

// resolvePins settles the two trust anchors, reading them from the Agentfile
// when one was named.
//
// A flag that contradicts the Agentfile is refused rather than silently
// preferred. These values are what the verification is held to, so two
// different answers to "which key do we trust" is a question the operator
// has to settle, not one this command should quietly pick a side in. Giving
// the same value twice is not a contradiction and passes.
func (a auditVerifyArgs) resolvePins() (expectedDID, approverPubkey string, err error) {
	if a.agentfile == "" {
		return a.did, a.approverPubkey, nil
	}

	m, err := manifest.ParseFile(a.agentfile)
	if err != nil {
		return "", "", fmt.Errorf("cannot read the Agentfile at %s: %w", a.agentfile, err)
	}

	expectedDID, err = reconcilePin("--did", "identity.did", a.did, m.Identity.DID, a.agentfile)
	if err != nil {
		return "", "", err
	}
	approverPubkey, err = reconcilePin(
		"--approver-pubkey", "human_gates.approver_pubkey",
		a.approverPubkey, m.HumanGates.ApproverPubkey, a.agentfile)
	if err != nil {
		return "", "", err
	}
	return expectedDID, approverPubkey, nil
}

// reconcilePin picks between a flag and an Agentfile field, refusing a
// disagreement.
func reconcilePin(flag, field, explicit, declared, agentfile string) (string, error) {
	switch {
	case explicit == "":
		return declared, nil
	case declared == "" || declared == explicit:
		return explicit, nil
	default:
		return "", fmt.Errorf(
			"%s=%s contradicts %s in %s (%s) — pass one or the other, not two different "+
				"answers to which key this log is held to",
			flag, explicit, field, agentfile, declared)
	}
}

// describePins names which anchors an Agentfile actually supplied, so a flag
// that resolved nothing cannot look like a pin that happened.
func describePins(expectedDID, approverPubkey string) string {
	switch {
	case expectedDID != "" && approverPubkey != "":
		return "identity.did, human_gates.approver_pubkey"
	case expectedDID != "":
		return "identity.did only — it declares no approver_pubkey, so gate decisions are unpinned"
	case approverPubkey != "":
		return "human_gates.approver_pubkey only — it declares no identity.did"
	default:
		return "it declares neither identity.did nor approver_pubkey — nothing was pinned"
	}
}

// auditVerifyUsage is the one usage string `constle audit verify` reports,
// shared with main's dispatch so the two cannot drift.
const auditVerifyUsage = "usage: constle audit verify [--agentfile=<path>] [--did=<did:key:…>] [--approver-pubkey=<did:key:…>] <logfile>"
