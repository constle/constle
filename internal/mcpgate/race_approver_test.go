package mcpgate

import (
	"context"
	"testing"
	"time"

	"github.com/constle/constle/internal/audit"
)

// reasonedApprover is a fixedApprover that also implements ReasoningApprover,
// so RaceApprover tests can assert DecidedBy/Event propagate through.
type reasonedApprover struct {
	fixedApprover
	decidedBy string
	event     audit.EventType
}

func (a *reasonedApprover) DecideWithReason(ctx context.Context, req Request) Outcome {
	return Outcome{Decision: a.Decide(ctx, req), DecidedBy: a.decidedBy, Event: a.event}
}

func TestRaceApproverFirstDecisionWins(t *testing.T) {
	race := RaceApprover{Approvers: []Approver{
		&fixedApprover{decision: DecisionApproved, delay: 10 * time.Millisecond},
		&fixedApprover{decision: DecisionDenied, delay: 200 * time.Millisecond},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if got := race.Decide(ctx, Request{}); got != DecisionApproved {
		t.Errorf("Decide() = %v, want DecisionApproved (the faster source)", got)
	}
}

func TestRaceApproverSlowerSourceLoses(t *testing.T) {
	race := RaceApprover{Approvers: []Approver{
		&fixedApprover{decision: DecisionDenied, delay: 10 * time.Millisecond},
		&fixedApprover{decision: DecisionApproved, delay: 200 * time.Millisecond},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if got := race.Decide(ctx, Request{}); got != DecisionDenied {
		t.Errorf("Decide() = %v, want DecisionDenied (the faster source)", got)
	}
}

func TestRaceApproverAllTimeOut(t *testing.T) {
	race := RaceApprover{Approvers: []Approver{
		&fixedApprover{decision: DecisionApproved, delay: time.Hour},
		&fixedApprover{decision: DecisionDenied, delay: time.Hour},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	if got := race.Decide(ctx, Request{}); got != DecisionNone {
		t.Errorf("Decide() = %v, want DecisionNone when every source times out", got)
	}
}

func TestRaceApproverPropagatesReasonFromWinner(t *testing.T) {
	race := RaceApprover{Approvers: []Approver{
		&reasonedApprover{
			fixedApprover: fixedApprover{decision: DecisionDenied, delay: 5 * time.Millisecond},
			decidedBy:     "webhook",
			event:         audit.EventGateSignatureInvalid,
		},
		&fixedApprover{decision: DecisionApproved, delay: 200 * time.Millisecond},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	outcome := race.DecideWithReason(ctx, Request{})
	if outcome.Decision != DecisionDenied {
		t.Fatalf("Decision = %v, want DecisionDenied", outcome.Decision)
	}
	if outcome.DecidedBy != "webhook" {
		t.Errorf("DecidedBy = %q, want webhook", outcome.DecidedBy)
	}
	if outcome.Event != audit.EventGateSignatureInvalid {
		t.Errorf("Event = %q, want %q", outcome.Event, audit.EventGateSignatureInvalid)
	}
}

func TestRaceApproverPlainApproverGetsDefaultAttribution(t *testing.T) {
	// A source that only implements Approver (not ReasoningApprover) — like
	// TerminalApprover — must still work: its win carries an empty
	// DecidedBy/Event, leaving runGate's own defaults in place.
	race := RaceApprover{Approvers: []Approver{
		&fixedApprover{decision: DecisionApproved, delay: 5 * time.Millisecond},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	outcome := race.DecideWithReason(ctx, Request{})
	if outcome.Decision != DecisionApproved {
		t.Fatalf("Decision = %v, want DecisionApproved", outcome.Decision)
	}
	if outcome.DecidedBy != "" || outcome.Event != "" {
		t.Errorf("outcome = %+v, want empty DecidedBy/Event for a plain Approver", outcome)
	}
}
