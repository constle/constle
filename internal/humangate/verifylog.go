package humangate

import (
	"fmt"

	"github.com/constle/constle/internal/audit"
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
	// Unproven lists entries claiming a webhook decision that record no
	// signed decision to back it up.
	Unproven []DecisionProblem
	// Failures lists recorded decisions whose cryptography disagrees with
	// what the log says happened.
	Failures []DecisionProblem
}

// DecisionProblem localizes one problem to one entry of the log.
type DecisionProblem struct {
	Entry     int // 1-based position in the file
	Event     audit.EventType
	RequestID string
	Detail    string
}

func (p DecisionProblem) String() string {
	id := p.RequestID
	if id == "" {
		id = "(no request_id)"
	}
	return fmt.Sprintf("entry %d: %s %s — %s", p.Entry, p.Event, id, p.Detail)
}

// OK reports whether every recorded decision held up.
//
// Unproven entries are deliberately not counted here: see VerifyDecisions
// for why an absence of evidence is only conclusive within a log that
// records evidence at all.
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
			// No evidence. That is correct and expected for a gate the
			// terminal answered, and for every entry written before spec
			// 0.4.0 — but not for an entry that names the webhook as the
			// source of its decision.
			if claimsUnprovenApproval(e) {
				rep.Unproven = append(rep.Unproven, problem(
					"the call was approved by the webhook approver, but no signed decision is "+
						"recorded to prove the approver ever gave one"))
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
				fail("the call was approved by the webhook approver, but no signed " +
					"decision is recorded to prove the approver ever gave one")
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

	// An absence of evidence only means something in a log that carries
	// evidence elsewhere. A log written entirely by an older constle records
	// none anywhere, and reporting every one of its gates as unproven would
	// bury the case that matters under a false alarm. A log that proves some
	// of its webhook decisions and not others is the real signal, so those
	// unproven entries are promoted to failures.
	if rep.Verified > 0 || rep.Unanswered > 0 {
		rep.Failures = append(rep.Failures, rep.Unproven...)
		rep.Unproven = nil
	}

	return rep, nil
}

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
