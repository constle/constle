package spending

import (
	"fmt"
	"testing"
)

func TestParseUSD(t *testing.T) {
	good := map[string]MicroCents{
		"0":          0,
		"0.00":       0,
		"1":          100_000_000,
		"1.50":       150_000_000,
		"0.50":       50_000_000,
		"5.00":       500_000_000,
		"0.000003":   300,
		"0.00000001": 1,
		".25":        25_000_000,
		"92000000":   9_200_000_000_000_000,
	}
	for in, want := range good {
		got, err := ParseUSD(in)
		if err != nil {
			t.Errorf("ParseUSD(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseUSD(%q) = %d, want %d", in, got, want)
		}
	}

	bad := []string{
		"", " ", "-1", "+1", "1e-6", "0.000000001", // 9 decimals — finer than 1e-8
		"1.2.3", "abc", "$1", "1,000", "0x10",
		"99999999999999999999", // overflows int64 micro-cents
	}
	for _, in := range bad {
		if got, err := ParseUSD(in); err == nil {
			t.Errorf("ParseUSD(%q) = %d, want error", in, got)
		}
	}
}

func TestUSDString(t *testing.T) {
	cases := map[MicroCents]string{
		0:           "0.00",
		1:           "0.00000001",
		300:         "0.000003",
		50_000_000:  "0.50",
		150_000_000: "1.50",
	}
	for in, want := range cases {
		if got := in.USD(); got != want {
			t.Errorf("(%d).USD() = %q, want %q", in, got, want)
		}
	}
}

func TestCostExact(t *testing.T) {
	// 1234 tokens at $0.000003/token = $0.003702 exactly.
	c, err := Cost("1234", 300)
	if err != nil {
		t.Fatal(err)
	}
	if want := MicroCents(370200); c != want {
		t.Errorf("Cost = %d, want %d", c, want)
	}

	// Fractional usage rounds UP: 1.5 units at 1 µ¢ (odd halves) → 2 µ¢.
	c, err = Cost("1.5", 1)
	if err != nil {
		t.Fatal(err)
	}
	if c != 2 {
		t.Errorf("Cost(1.5 × 1µ¢) = %d, want 2 (ceiling)", c)
	}

	if _, err := Cost("-5", 300); err == nil {
		t.Error("negative usage must be rejected")
	}
	if _, err := Cost("garbage", 300); err == nil {
		t.Error("non-numeric usage must be rejected")
	}
	if _, err := Cost("9999999999999999999999", 100_000_000); err == nil {
		t.Error("overflowing cost must be rejected")
	}
}

// TestAccumulationZeroDrift is the accounting-precision deliverable: a
// million small charges sum exactly, with zero drift — the reason float64
// was rejected (summing 0.000003 a million times in float64 does NOT give
// exactly 3.0).
func TestAccumulationZeroDrift(t *testing.T) {
	perCharge, err := Cost("1", 300) // $0.000003
	if err != nil {
		t.Fatal(err)
	}

	var total MicroCents
	const n = 1_000_000
	for i := 0; i < n; i++ {
		total, err = Add(total, perCharge)
		if err != nil {
			t.Fatal(err)
		}
	}

	if want := MicroCents(n * 300); total != want {
		t.Fatalf("accumulated %d µ¢, want exactly %d µ¢ — integer accounting drifted", total, want)
	}
	if got := total.USD(); got != "3.00" {
		t.Fatalf("total = %s USD, want exactly 3.00", got)
	}

	// The float64 control: the same accumulation demonstrably drifts.
	f := 0.0
	for i := 0; i < n; i++ {
		f += 0.000003
	}
	if fmt.Sprintf("%.10f", f) == "3.0000000000" {
		t.Log("float64 happened not to drift on this platform — integer requirement stands regardless")
	}
}
