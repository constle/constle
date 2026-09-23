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
	pins, err := a.resolvePins()
	if err != nil {
		return err
	}
	expectedDID, approverPubkey := pins.did, pins.approverPubkey

	// Settle the trust anchor before reading anything. A pin that is not a
	// usable key is an operator error about what this run is held to, and
	// reporting it only after a whole log has verified would tell them the
	// log is fine in the same breath as telling them nothing checked it
	// against the key they named. Passing no entries makes this exactly a
	// validation of the pin.
	if approverPubkey != "" {
		if _, err := humangate.VerifyDecisions(nil, approverPubkey); err != nil {
			return fmt.Errorf("%s", termsafe.Line(err.Error()))
		}
	}

	report, err := audit.VerifyFile(path, expectedDID)
	if err != nil {
		if te, ok := err.(*audit.TamperError); ok {
			// The newline here is constle's own; the two values around it
			// are not. Escaped individually so neither can add a third line
			// of its own — errf's Block backstop removes control bytes but
			// deliberately keeps newlines, and cannot tell which of them
			// this format string wrote.
			return fmt.Errorf("TAMPERING DETECTED in %s\n  %s",
				termsafe.Line(path), termsafe.Line(te.Error()))
		}
		// Not a tamper report: a filesystem or read error, whose text
		// quotes the path it failed on.
		return fmt.Errorf("%s", termsafe.Line(err.Error()))
	}

	decisions, err := humangate.VerifyDecisions(report.Parsed, approverPubkey)
	if err != nil {
		// Quotes the rejected pin, which came off the command line or the
		// Agentfile.
		return fmt.Errorf("%s", termsafe.Line(err.Error()))
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
		// Same reason #54 wraps path a few lines up: whatever the operator
		// typed on the command line.
		printf("%s", pinsFromLine(a.agentfile, pins))
	}
	printf("\n")

	reportGateDecisions(decisions, approverPubkey)
	if !decisions.OK() {
		return fmt.Errorf("%d human-gate decision(s) in %s do not hold up — see above",
			len(decisions.Failures), termsafe.Line(path))
	}
	return nil
}

// reportGateDecisions prints the §9 decision check. It stays silent for a
// log with no gate decisions in it, rather than printing a row of zeros for
// every run that never gated a call.
func reportGateDecisions(d *humangate.DecisionReport, approverPubkey string) {
	if d.Verified == 0 && d.Unanswered == 0 && len(d.Failures) == 0 {
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
func (a auditVerifyArgs) resolvePins() (resolvedPins, error) {
	if a.agentfile == "" {
		return resolvedPins{did: a.did, approverPubkey: a.approverPubkey}, nil
	}

	m, err := manifest.ParseFile(a.agentfile)
	if err != nil {
		// Both halves are attacker-shaped: the path is whatever was typed,
		// and a parser or filesystem error quotes it back. Escaped before
		// formatting, not after — errf's Block backstop strips control
		// bytes but deliberately keeps newlines, so a path containing one
		// would otherwise write a second line that reads as constle's own.
		// The wrap is dropped with it; nothing inspects this error, it is
		// reported and the process exits.
		return resolvedPins{}, fmt.Errorf("cannot read the Agentfile at %s: %s",
			termsafe.Line(a.agentfile), termsafe.Line(err.Error()))
	}

	p := resolvedPins{
		declaredDID:      m.Identity.DID,
		declaredApprover: m.HumanGates.ApproverPubkey,
	}
	if p.did, err = reconcilePin("--did", "identity.did", a.did, p.declaredDID, a.agentfile); err != nil {
		return resolvedPins{}, err
	}
	if p.approverPubkey, err = reconcilePin(
		"--approver-pubkey", "human_gates.approver_pubkey",
		a.approverPubkey, p.declaredApprover, a.agentfile); err != nil {
		return resolvedPins{}, err
	}
	return p, nil
}

// resolvedPins is the outcome of settling the two trust anchors, and a
// record of which of them the Agentfile itself supplied.
//
// The provenance is kept separately from the values because the report line
// makes a claim about where a pin came from. A flag can supply a pin the
// file omits, and saying "pins from: <file>" over that would credit the file
// with a pin it never declared — the same species of overclaim §9 was
// rewritten to remove.
type resolvedPins struct {
	did, approverPubkey           string
	declaredDID, declaredApprover string
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
		// Every interpolated value here came off the command line or out of
		// the Agentfile. Escaped individually for the reason given in
		// resolvePins.
		return "", fmt.Errorf(
			"%s=%s contradicts %s in %s (%s) — pass one or the other, not two different "+
				"answers to which key this log is held to",
			flag, termsafe.Line(explicit), field, termsafe.Line(agentfile), termsafe.Line(declared))
	}
}

// pinsFromLine reports what an Agentfile actually contributed, as one
// escaped line ready to print.
//
// It describes the FILE's declarations rather than the resolved values, so a
// pin that arrived on the command line is never presented as having come
// from the file.
func pinsFromLine(agentfile string, p resolvedPins) string {
	var what string
	switch {
	case p.declaredDID != "" && p.declaredApprover != "":
		what = "identity.did, human_gates.approver_pubkey"
	case p.declaredDID != "":
		what = "identity.did only — it declares no approver_pubkey"
		if p.approverPubkey == "" {
			what += ", so gate decisions are unpinned"
		}
	case p.declaredApprover != "":
		what = "human_gates.approver_pubkey only — it declares no identity.did"
	default:
		what = "it declares neither identity.did nor approver_pubkey"
	}
	return fmt.Sprintf("  pins from: %s (%s)\n", termsafe.Line(agentfile), what)
}

// auditVerifyUsage is the one usage string `constle audit verify` reports,
// shared with main's dispatch so the two cannot drift.
const auditVerifyUsage = "usage: constle audit verify [--agentfile=<path>] [--did=<did:key:…>] [--approver-pubkey=<did:key:…>] <logfile>"
