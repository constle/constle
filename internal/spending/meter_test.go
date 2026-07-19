package spending

import "testing"

const sampleResponse = `{
  "jsonrpc": "2.0",
  "id": 7,
  "result": {
    "content": [{"type": "text", "text": "done"}],
    "usage": {"input_tokens": 100, "output_tokens": 250, "note": "free-form"}
  }
}`

func mustPath(t *testing.T, p string) []string {
	t.Helper()
	segs, err := ParsePath(p)
	if err != nil {
		t.Fatalf("ParsePath(%q): %v", p, err)
	}
	return segs
}

func TestExtractUsage(t *testing.T) {
	got, err := ExtractUsage([]byte(sampleResponse), mustPath(t, "result.usage.output_tokens"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "250" {
		t.Errorf("got %q, want 250", got)
	}

	// Array indexing with a digit segment.
	got, err = ExtractUsage([]byte(`{"result":{"items":[{"n":5},{"n":9}]}}`), mustPath(t, "result.items.1.n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "9" {
		t.Errorf("got %q, want 9", got)
	}

	// Exactness: a number that float64 would mangle survives verbatim.
	got, err = ExtractUsage([]byte(`{"u": 9007199254740993}`), mustPath(t, "u"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "9007199254740993" {
		t.Errorf("got %q — usage went through float64", got)
	}

	for _, p := range []string{"result.usage.missing", "result.usage.note", "result.content.5", "nope"} {
		if _, err := ExtractUsage([]byte(sampleResponse), mustPath(t, p)); err == nil {
			t.Errorf("path %q: want error, got none", p)
		}
	}
}

func TestParsePathRejectsBadPaths(t *testing.T) {
	for _, p := range []string{"", " ", "a..b", ".a", "a."} {
		if _, err := ParsePath(p); err == nil {
			t.Errorf("ParsePath(%q): want error", p)
		}
	}
}

func TestMeterResponseSumsAllMeters(t *testing.T) {
	meters := []Meter{
		{Path: mustPath(t, "result.usage.input_tokens"), Price: 300},   // $0.000003
		{Path: mustPath(t, "result.usage.output_tokens"), Price: 1500}, // $0.000015
	}
	total, err := MeterResponse([]byte(sampleResponse), meters)
	if err != nil {
		t.Fatal(err)
	}
	// 100×300 + 250×1500 = 30000 + 375000 = 405000 µ¢ = $0.00405
	if want := MicroCents(405000); total != want {
		t.Errorf("total = %d, want %d", total, want)
	}

	// One meter missing its value fails the WHOLE response (server-wide
	// pricing: no partial, silently-cheaper metering).
	meters = append(meters, Meter{Path: mustPath(t, "result.usage.cache_tokens"), Price: 1})
	if _, err := MeterResponse([]byte(sampleResponse), meters); err == nil {
		t.Error("missing meter value must fail the whole response")
	}
}
