package spending

import "testing"

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
