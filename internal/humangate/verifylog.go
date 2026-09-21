package humangate

import (
	"fmt"
	"unicode/utf8"

	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/termsafe"
	"github.com/constle/constle/pkg/did"
)

// DecisionReport summarizes an offline re-verification of the signed gate
// decisions recorded in one audit log (spec §9).
type DecisionReport struct {
	// Verified counts decisions whose recorded signature reproduces exactly
	// the outcome the log claims for them.
	Verified int
	// Unanswered counts gates that were opened on the decision endpoint and
	// timed out with no decision to verify.
	Unanswered int
	// Failures lists every entry whose claim the cryptography does not
	// support — including an approval that records no decision at all.
	Failures []DecisionProblem
}

// DecisionProblem localizes one problem to one entry of the log.
type DecisionProblem struct {
	Entry     int // 1-based position in the file
	Event     audit.EventType
	RequestID string
	Detail    string
}

// String renders one problem for an operator to read. Every part of it that
// came out of the log is escaped and bounded first — see safeProblemField.
func (p DecisionProblem) String() string {
	id := safeProblemField(p.RequestID)
	if id == "" {
		id = "(no request_id)"
	}
	// Detail is composed here or by a stdlib error over an already-bounded
	// field, so it is escaped without a length bound of its own. Escaped
	// rather than trusted, because "constle wrote it" is a claim about the
	// format string, not about what got interpolated into it.
	return fmt.Sprintf("entry %d: %s %s — %s",
		p.Entry, safeProblemField(string(p.Event)), id, termsafe.Line(p.Detail))
}

// safeProblemField renders one field of a problem line that arrived out of
// the log under examination.
//
// Those fields are not trustworthy as text, and passing verification does not
// make them so: internal/audit's own verifier documents that a wholly
// attacker-authored log is internally consistent by construction, and this
// package is reached precisely when a log's claims are in question. The log
// is also designed to travel, so the machine reading it is not the machine
// that wrote it.
//
// Escaping happens BEFORE the value is formatted into the line, which is the
// rule internal/termsafe states for this exact case: Block, the backstop
// underneath, cannot tell a newline the format string wrote from one that
// arrived inside an interpolated value — so a value that could end its own
// line has to be escaped first, or it can write a line that reads as constle
// speaking. Here that line is a verdict about whether an approval was real.
//
// The length bound is internal/audit quoteDID's reasoning, with one
// difference: it applies AFTER escaping. Escaping expands — one control byte
// becomes six printable ones — so a cap taken first would not be a cap on
// what is printed. It is enforced here rather than inherited from the
// EvidenceFieldMax the records are written under, because String is exported
// and a DecisionProblem can be built out of anything; the constant is reused
// because it is already this package's answer to how long one of these may
// legitimately be.
func safeProblemField(s string) string {
	s = termsafe.Line(s)
	if len(s) <= EvidenceFieldMax {
		return s
	}
	// Cut on a rune boundary: the escaped string is printable, but a byte
	// slice can still split a multi-byte rune and produce the invalid UTF-8
	// this function exists to keep out.
	cut := EvidenceFieldMax
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return fmt.Sprintf("%s… (%d bytes in all)", s[:cut], len(s))
}

// OK reports whether every webhook approval in the log is backed by a
// signature that supports it.
func (r *DecisionReport) OK() bool { return len(r.Failures) == 0 }

// VerifyDecisions re-verifies, offline, every signed gate decision recorded
// in a log — the check spec §9 exists to make possible.
//
// The question it answers is not "does this signature verify" but "does the
// cryptography agree with what the log claims happened". A log line saying
// gate_approved is a statement by the runtime; the recorded signature is a
// statement by the approver. Checking only the former re-reads the runtime's
// own claim back to itself, which is precisely the gap HG02 named. So every
// terminal gate event is mapped to the VerifyDecision reason that must
// reproduce it, and a disagreement in either direction is a failure:
//
//   - gate_approved that does not re-verify as approved is an approval the
//     declared approver never gave.
//   - gate_signature_invalid (or either mismatch event) that now verifies
//     cleanly is a denial the log misattributes to the approver.
//
// pinnedPubkey is the approver_pubkey the caller trusts, normally read from
// the Agentfile. Passing "" falls back to the key each entry records, which
// verifies the log's internal consistency but not its trust anchor: a
// runtime that swapped the approver key produces entries that verify
// perfectly against the swapped key. Pinning is what turns that into a
// visible disagreement, which is the whole reason the key is recorded.
//
// It does not, and cannot, close spec §10's host-coercion limitation. A host
// that lies at gate time lies before any of this is written. What it closes
// is the gap after the fact: a decision that was never signed can no longer
// be recorded as though it had been.
func VerifyDecisions(entries []audit.Entry, pinnedPubkey string) (*DecisionReport, error) {
	if pinnedPubkey != "" {
		if _, err := did.PublicKey(pinnedPubkey); err != nil {
			return nil, fmt.Errorf("pinned approver_pubkey is not a valid did:key Ed25519 string: %w", err)
		}
	}

	rep := &DecisionReport{}
	for i, e := range entries {
		problem := func(detail string, args ...any) DecisionProblem {
			return DecisionProblem{Entry: i + 1, Event: e.Event, Detail: fmt.Sprintf(detail, args...)}
		}

		rec, err := RecordedDecisionFrom(e.Details)
		if err != nil {
			rep.Failures = append(rep.Failures, problem("%v", err))
			continue
		}

		if rec == nil {
			// No evidence. Correct and expected for a gate the terminal
			// answered; a failure for one that says the webhook let a call
			// through.
			if claimsUnprovenApproval(e) {
				rep.Failures = append(rep.Failures, problem("%s", unprovenApproval))
			}
			continue
		}

		p := problem("")
		p.RequestID = rec.Request.RequestID
		fail := func(detail string, args ...any) {
			p.Detail = fmt.Sprintf(detail, args...)
			rep.Failures = append(rep.Failures, p)
		}

		if rec.Response == nil {
			// Evidence with no decision in it. That is what an unanswered
			// gate looks like: gate_timeout records the request alone, so
			// the gate can be correlated with the receiver's own log by
			// request_id, and nothing was signed to check.
			//
			// On gate_approved it is something else entirely — a call that
			// ran, carrying a record of having asked and none of any
			// answer. Arriving here through a recorded request rather than
			// through no evidence at all changes nothing about what that
			// is, so it fails exactly as claimsUnprovenApproval fails it.
			switch e.Event {
			case audit.EventGateApproved:
				fail("%s", unprovenApproval)
			case audit.EventGateTimeout:
				rep.Unanswered++
			}
			continue
		}

		// The entry's own subject_digest is the one the gate computed
		// independently for the prompt. If the request record names a
		// different subject, the two halves of the same entry disagree
		// about which call was gated, and no signature over either one
		// settles which is the real subject.
		if d, ok := e.Details["subject_digest"].(string); ok &&
			d != "" && rec.Request.SubjectDigest != "" && d != rec.Request.SubjectDigest {
			fail("the gated call's subject_digest is %s but the recorded request names %s",
				d, rec.Request.SubjectDigest)
			continue
		}

		// Same rule applied to the tool name. This catches a decision record
		// pasted onto an entry it does not belong to, and it deliberately
		// does not claim more: a runtime that rewrites BOTH halves passes,
		// because both halves are written by the same runtime. What no
		// check here can do is tie the tool NAME to the subject_digest —
		// the digest commits to the name and the arguments together, and
		// recomputing it needs the arguments, which §9 excludes on purpose.
		// A captured approval can therefore be relabelled as a different
		// call by whoever writes the log. That residual is stated in spec
		// §10; the request_id recorded alongside is what lets the approver's
		// own records settle it.
		if name, ok := e.Details["tool"].(string); ok &&
			name != "" && rec.Request.ToolName != "" && name != rec.Request.ToolName {
			fail("the gated call names tool %q but the recorded request names %q",
				name, rec.Request.ToolName)
			continue
		}

		pub := rec.ApproverPubkey
		if pinnedPubkey != "" {
			if rec.ApproverPubkey != "" && rec.ApproverPubkey != pinnedPubkey {
				fail("the decision was verified against approver_pubkey %s, not the pinned %s — "+
					"the approver key in use was not the one trusted here",
					rec.ApproverPubkey, pinnedPubkey)
				continue
			}
			pub = pinnedPubkey
		}
		if pub == "" {
			fail("no approver_pubkey was recorded and none was pinned, so the decision " +
				"cannot be attributed to any approver")
			continue
		}

		if rec.Response.Truncated {
			fail("the recorded decision exceeded %d bytes per field and was truncated when "+
				"written, so its signed payload can no longer be reproduced",
				EvidenceFieldMax)
			continue
		}

		want, ok := terminalReason(e.Event)
		if !ok {
			fail("a signed decision is recorded on %s, which is not an event a gate decision "+
				"produces", e.Event)
			continue
		}

		_, got, verr := VerifyDecision(pub, rec.Request.RequestID, rec.Request.SubjectDigest, rec.Response.wire())
		if got != want {
			fail("the log records %s, but the signed decision verifies as %s (%v)", e.Event, got, verr)
			continue
		}
		rep.Verified++
	}

	return rep, nil
}

// unprovenApproval is the one thing this whole check exists to catch.
//
// An earlier revision reported it only when some OTHER entry in the same log
// carried evidence, so that a log written before spec 0.4.0 would not have
// every gate in it reported as a failure. That inference was the hole: a log
// with the evidence stripped from every approval is byte-for-byte the shape
// it inferred as "old", so removing all of it passed. An absence of proof
// cannot be excused by the absence being thorough, and a daily file mixing
// runs from two versions made the same inference flip per entry. Principle:
// a missing or unverifiable security signal fails loudly; it never succeeds
// quietly.
const unprovenApproval = "the call was approved by the webhook approver, but no signed decision " +
	"is recorded to prove the approver ever gave one — a log written before spec 0.4.0 " +
	"records none, and is indistinguishable from one the record was removed from"

// claimsUnprovenApproval reports whether an entry says the webhook approver
// let a call through while recording nothing that could show it did.
//
// Deliberately approvals only. A webhook DENIAL with no evidence is the
// fail-closed direction — the call was blocked, and nothing about blocking
// a call needs an approver's signature to justify it. Two such denials are
// even reachable by design: DecideWithReason denies before any request
// exists if the subject digest or the request body cannot be built, and
// demanding proof of a decision that was never asked for would report the
// runtime's own safety check as a missing record. The asymmetry is the
// point of the whole finding: what has to be provable is a call that ran.
func claimsUnprovenApproval(e audit.Entry) bool {
	if e.Event != audit.EventGateApproved {
		return false
	}
	by, _ := e.Details[DetailDecidedBy].(string)
	return by == DecidedByWebhook
}

// terminalReason maps a terminal gate event onto the VerifyDecision reason
// that must reproduce it. gate_triggered is absent because it is written
// before a request_id exists, and gate_timeout because nothing was signed.
func terminalReason(event audit.EventType) (Reason, bool) {
	switch event {
	case audit.EventGateApproved:
		return ReasonApproved, true
	case audit.EventGateDenied:
		return ReasonNotApproved, true
	case audit.EventGateSignatureInvalid:
		return ReasonSignatureInvalid, true
	case audit.EventGateRequestIDMismatch:
		return ReasonRequestIDMismatch, true
	case audit.EventGateDigestMismatch:
		return ReasonDigestMismatch, true
	}
	return "", false
}
