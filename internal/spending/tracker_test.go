package spending

import (
	"math"
	"testing"
)

func TestTrackerPerRunCap(t *testing.T) {
	tr, err := NewTracker(Limits{PerRun: 1000}, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := tr.Charge("run", "srv", 600)
	if err != nil {
		t.Fatal(err)
	}
	if res.Violation != ViolationNone {
		t.Fatalf("under-cap charge tripped: %+v", res)
	}

	// Exactly at the cap is still allowed — "max" is inclusive.
	res, err = tr.Charge("run", "srv", 400)
	if err != nil {
		t.Fatal(err)
	}
	if res.Violation != ViolationNone {
		t.Fatalf("at-cap charge tripped: %+v", res)
	}

	res, err = tr.Charge("run", "srv", 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Violation != ViolationPerRun {
		t.Fatalf("over-cap charge did not trip per-run: %+v", res)
	}
	if tr.Tripped() != ViolationPerRun {
		t.Error("tracker not tripped after violation")
	}

	// Once tripped, stays tripped.
	res, _ = tr.Charge("run", "srv", 1)
	if res.Violation != ViolationPerRun {
		t.Error("tripped tracker must stay tripped")
	}
}

func TestTrackerDailyCapIncludesPriorSpend(t *testing.T) {
	store := testStore(t)
	// A previous run already spent 900 today.
	if _, err := store.Append("previous-run", "srv", 900); err != nil {
		t.Fatal(err)
	}

	// This run's own cap (per-run) is far away; only the daily cap can trip.
	tr, err := NewTracker(Limits{PerRun: 1_000_000, PerDay: 1000}, store)
	if err != nil {
		t.Fatal(err)
	}

	res, err := tr.Charge("run", "srv", 50)
	if err != nil {
		t.Fatal(err)
	}
	if res.DayTotal != 950 || res.Violation != ViolationNone {
		t.Fatalf("res = %+v, want day total 950, no violation", res)
	}

	res, err = tr.Charge("run", "srv", 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.Violation != ViolationPerDay {
		t.Fatalf("crossing the daily cap via prior spend did not trip: %+v", res)
	}
	if res.RunTotal != 150 {
		t.Errorf("run total = %d, want 150 — this run alone is under its per-run cap", res.RunTotal)
	}
}

func TestTrackerWarnThresholdFiresOnce(t *testing.T) {
	store := testStore(t)
	tr, err := NewTracker(Limits{PerDay: 10_000, WarnAtPctOfDaily: 80}, store)
	if err != nil {
		t.Fatal(err)
	}

	res, err := tr.Charge("run", "srv", 7999)
	if err != nil {
		t.Fatal(err)
	}
	if res.WarnCrossed {
		t.Fatal("warn fired below the threshold")
	}

	res, err = tr.Charge("run", "srv", 1) // 8000 = exactly 80%
	if err != nil {
		t.Fatal(err)
	}
	if !res.WarnCrossed {
		t.Fatal("warn did not fire at the threshold")
	}

	res, err = tr.Charge("run", "srv", 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.WarnCrossed {
		t.Fatal("warn fired twice")
	}
}

func TestTrackerDailyCapRequiresStore(t *testing.T) {
	if _, err := NewTracker(Limits{PerDay: 1}, nil); err == nil {
		t.Fatal("a daily cap without a durable store must be refused")
	}
}

// TestTrackerRejectsNegativeLimits pins the gate that makes a negative cap
// impossible to enforce-as-no-cap. Charge reads "> 0" as "declared", so a
// negative limit would sail through every check: no trip on any charge, and
// (for PerDay) no durable store demanded either. The tracker must not be
// constructible in that state at all.
func TestTrackerRejectsNegativeLimits(t *testing.T) {
	for name, limits := range map[string]Limits{
		"per-run":  {PerRun: -1},
		"per-day":  {PerDay: -1},
		"both":     {PerRun: -1, PerDay: -1},
		"min-int":  {PerRun: math.MinInt64},
		"with-day": {PerRun: -1, PerDay: 1000},
	} {
		if _, err := NewTracker(limits, testStore(t)); err == nil {
			t.Errorf("%s: a negative cap must be refused, got a usable tracker", name)
		}
	}

	// The specific escape this closes: a negative PerDay used to skip the
	// "daily cap needs durable state" rule, because that rule is also "> 0".
	if _, err := NewTracker(Limits{PerDay: -1}, nil); err == nil {
		t.Fatal("a negative daily cap with no store must be refused")
	}

	// WarnAtPctOfDaily is read the same way, so it is bounded too. A negative
	// threshold used to mean "no warning" instead of being refused.
	if _, err := NewTracker(Limits{PerDay: 1000, WarnAtPctOfDaily: -1}, testStore(t)); err == nil {
		t.Error("a negative warn threshold must be refused")
	}
	if _, err := NewTracker(Limits{PerDay: 1000, WarnAtPctOfDaily: 101}, testStore(t)); err == nil {
		t.Error("a warn threshold above 100 must be refused")
	}

	// Zero still means "not declared", and must stay constructible.
	if _, err := NewTracker(Limits{}, nil); err != nil {
		t.Fatalf("undeclared limits must remain valid: %v", err)
	}
	if _, err := NewTracker(Limits{PerDay: 1000, WarnAtPctOfDaily: 80}, testStore(t)); err != nil {
		t.Fatalf("a valid warn threshold must remain valid: %v", err)
	}

	// Charge computes the warning against PerDay, so a threshold with no daily
	// cap is a declared warning nothing can ever raise.
	if _, err := NewTracker(Limits{PerRun: 1000, WarnAtPctOfDaily: 80}, nil); err == nil {
		t.Error("a warn threshold with no daily cap must be refused")
	}
}

// TestChargeRejectsNegativeAmount: a negative charge would subtract from the
// run total and hand budget back. The daily store refuses one on append, so
// only the store-less per-run path was exposed — a tracker could be walked
// back under its cap and then over it again without ever tripping.
func TestChargeRejectsNegativeAmount(t *testing.T) {
	tr, err := NewTracker(Limits{PerRun: 100}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Charge("run", "srv", -1000); err == nil {
		t.Fatal("a negative charge must be refused")
	}
	if got := tr.RunTotal(); got != 0 {
		t.Errorf("a refused charge must not move the run total, got %s", got.USD())
	}
	// And the cap still trips normally afterwards.
	res, err := tr.Charge("run", "srv", 101)
	if err != nil {
		t.Fatal(err)
	}
	if res.Violation != ViolationPerRun {
		t.Errorf("over-cap charge did not trip: %+v", res)
	}
}

func TestTrackerTripForMeteringFailure(t *testing.T) {
	tr, err := NewTracker(Limits{PerRun: 1000}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr.Trip(ViolationMetering)
	if tr.Tripped() != ViolationMetering {
		t.Fatal("Trip did not stick")
	}
	// A later real violation must not overwrite the original reason.
	tr.Trip(ViolationPerRun)
	if tr.Tripped() != ViolationMetering {
		t.Fatal("second Trip overwrote the first reason")
	}
}
