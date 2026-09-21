package mcpgate

import "context"

// RaceApprover composes several approval sources for one gate — e.g. the
// local terminal and an external decision endpoint — and returns whichever
// produces a decision first. This mirrors the webhook spec's model of an
// external decision channel as one more input to a gate, not a replacement
// for the terminal prompt: both stay live until one of them answers.
//
// Once one source's Decide/DecideWithReason returns a decision, every other
// source's context is canceled. Decide implementations that select on
// ctx.Done() — every Approver in this package does — then stop promptly;
// RaceApprover does not wait for them to actually finish before returning.
type RaceApprover struct {
	Approvers []Approver
}

// Decide implements Approver.
func (r RaceApprover) Decide(ctx context.Context, req Request) Decision {
	return r.DecideWithReason(ctx, req).Decision
}

// DecideWithReason implements ReasoningApprover: it races every configured
// approver and returns the first Outcome carrying a real decision, whether
// or not that particular source implements ReasoningApprover itself.
func (r RaceApprover) DecideWithReason(ctx context.Context, req Request) Outcome {
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan Outcome, len(r.Approvers))
	for _, a := range r.Approvers {
		go func(a Approver) {
			if ra, ok := a.(ReasoningApprover); ok {
				results <- ra.DecideWithReason(raceCtx, req)
				return
			}
			results <- Outcome{Decision: a.Decide(raceCtx, req)}
		}(a)
	}

	// A source that produced no decision can still have produced evidence:
	// a webhook approver that opened a gate nobody answered records the
	// request it sent, which is what lets the resulting gate_timeout be
	// correlated with the receiver's own log by request_id. Carrying the
	// first such record out keeps that from being lost to the drain below,
	// where every source has by now returned DecisionNone.
	var undecided Outcome
	for range r.Approvers {
		out := <-results
		if out.Decision != DecisionNone {
			return out
		}
		if undecided.Evidence == nil {
			undecided.Evidence = out.Evidence
		}
	}
	return undecided
}
