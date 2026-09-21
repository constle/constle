package spending

import (
	"fmt"
	"math/big"
	"sync"
)

// Limits are the enforced caps, already parsed to exact MicroCents.
// A zero cap means "not declared"; a negative one is refused by NewTracker.
type Limits struct {
	PerRun MicroCents
	PerDay MicroCents
	// WarnAtPctOfDaily fires a one-time warning event when the day total
	// crosses this percentage of PerDay (0 = no warning threshold).
	WarnAtPctOfDaily int
}

// Violation names which declared limit a charge crossed. The values are
// the manifest field names so audit events and errors read literally.
type Violation string

const (
	ViolationNone     Violation = ""
	ViolationPerRun   Violation = "max_per_run_usd"
	ViolationPerDay   Violation = "max_per_day_usd"
	ViolationMetering Violation = "metering_failure"
)

// Result describes the state after one charge was applied.
type Result struct {
	Amount   MicroCents
	RunTotal MicroCents
	// DayTotal includes prior runs (and concurrent runs) of the same DID.
	// Zero-valued and meaningless when no daily store is attached.
	DayTotal MicroCents
	// WarnCrossed is true exactly once: on the charge that first pushes the
	// day total over the warn_at_pct_of_daily threshold.
	WarnCrossed bool
	// Violation is non-empty when the tracker is tripped; the caller must
	// stop the run.
	Violation Violation
	// NewlyTripped is true only on the exact charge that crossed a cap —
	// the caller logs the limit event once, on that charge.
	NewlyTripped bool
}

// Tracker accumulates a run's metered spend and applies the caps. It is
// shared between gate goroutines; all methods are safe for concurrent use.
type Tracker struct {
	mu       sync.Mutex
	limits   Limits
	store    *DailyStore // nil when no daily cap is enforced
	runTotal MicroCents
	warned   bool
	tripped  Violation
}

// NewTracker builds a tracker for one run. store may be nil only when
// limits.PerDay is zero — a daily cap without durable state would reset on
// every process exit and enforce nothing. Negative caps are refused: see
// below for why the sign is settled here and not at each reader.
func NewTracker(limits Limits, store *DailyStore) (*Tracker, error) {
	// Every enforcement site reads "> 0" as "declared", so a negative cap is
	// indistinguishable from an unset one — it would skip the durable ledger,
	// skip the pre-run budget check, and leave both trip conditions in Charge
	// unreachable. Limits is an exported struct with exported fields and is
	// built field by field by its callers, so the guarantee is made at the one
	// gate every Tracker passes through rather than trusted to each reader.
	// Changing those readers to "!= 0" instead would be the opposite error: a
	// negative cap would then trip everything on the first charge.
	if limits.PerRun < 0 || limits.PerDay < 0 {
		return nil, fmt.Errorf(
			"spending limits must not be negative (max_per_run_usd=%s, max_per_day_usd=%s)",
			limits.PerRun.USD(), limits.PerDay.USD())
	}
	// Charge reads WarnAtPctOfDaily the same way — "> 0" means configured —
	// so a negative threshold silently means "no warning" rather than being
	// refused. Bounded here to the range the manifest validator already
	// requires, since this constructor is also reachable from Go directly.
	if limits.WarnAtPctOfDaily < 0 || limits.WarnAtPctOfDaily > 100 {
		return nil, fmt.Errorf("warn_at_pct_of_daily must be between 0 (unset) and 100, got %d", limits.WarnAtPctOfDaily)
	}
	// Charge computes the warning against PerDay, so a threshold without a
	// daily cap can never fire. The manifest validator already refuses that
	// pairing; refusing it here too keeps a declared warning from looking real
	// when nothing can raise it.
	if limits.WarnAtPctOfDaily > 0 && limits.PerDay <= 0 {
		return nil, fmt.Errorf("warn_at_pct_of_daily is set but there is no max_per_day_usd to warn about")
	}
	if limits.PerDay > 0 && store == nil {
		return nil, fmt.Errorf("max_per_day_usd requires a durable daily store")
	}
	return &Tracker{limits: limits, store: store}, nil
}

// Charge records one metered cost, durably appends it to the daily ledger
// (when one is attached), and reports threshold crossings. On the first
// violation the tracker trips and stays tripped. A storage error is
// returned as-is — the caller must treat it as a metering failure and fail
// closed, never as a free charge.
func (t *Tracker) Charge(runID, serverID string, amount MicroCents) (Result, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	res := Result{Amount: amount}

	// A negative charge would subtract from the run total and hand budget
	// back. Cost never produces one and the daily store refuses one on
	// append, so this only closes the store-less per-run path — but that is
	// the same "free budget" the ledger refuses, and it belongs on both.
	if amount < 0 {
		return res, fmt.Errorf("negative charge %s", amount.USD())
	}

	newRunTotal, err := Add(t.runTotal, amount)
	if err != nil {
		return res, err
	}

	if t.store != nil {
		// The charge is appended even when it crosses a cap: the cost was
		// already incurred (the response was consumed) — the ledger records
		// reality, enforcement stops what happens next.
		dayTotal, err := t.store.Append(runID, serverID, amount)
		if err != nil {
			return res, err
		}
		res.DayTotal = dayTotal
	}

	t.runTotal = newRunTotal
	res.RunTotal = newRunTotal

	if t.limits.PerDay > 0 && t.limits.WarnAtPctOfDaily > 0 && !t.warned {
		// DayTotal ≥ PerDay × pct/100, compared cross-multiplied in big.Int
		// so the threshold is exact and cannot overflow int64.
		lhs := new(big.Int).Mul(big.NewInt(int64(res.DayTotal)), big.NewInt(100))
		rhs := new(big.Int).Mul(big.NewInt(int64(t.limits.PerDay)), big.NewInt(int64(t.limits.WarnAtPctOfDaily)))
		if lhs.Cmp(rhs) >= 0 {
			t.warned = true
			res.WarnCrossed = true
		}
	}

	if t.tripped == ViolationNone {
		switch {
		case t.limits.PerRun > 0 && res.RunTotal > t.limits.PerRun:
			t.tripped = ViolationPerRun
			res.NewlyTripped = true
		case t.limits.PerDay > 0 && res.DayTotal > t.limits.PerDay:
			t.tripped = ViolationPerDay
			res.NewlyTripped = true
		}
	}
	res.Violation = t.tripped
	return res, nil
}

// Trip forces the tracker into the tripped state — used for metering
// failures, where no exact charge is known but the run must stop.
func (t *Tracker) Trip(v Violation) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tripped == ViolationNone {
		t.tripped = v
	}
}

// Tripped returns the violation that stopped this run, if any.
func (t *Tracker) Tripped() Violation {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tripped
}

// RunTotal returns the spend metered for this run so far.
func (t *Tracker) RunTotal() MicroCents {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.runTotal
}

// Limits returns the caps this tracker enforces.
func (t *Tracker) Limits() Limits {
	return t.limits
}
