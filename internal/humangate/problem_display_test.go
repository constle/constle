package humangate

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/constle/constle/internal/audit"
)

// TestProblemLineEscapesWhatCameOutOfTheLog: a DecisionProblem is built from
// an audit log's own bytes, and `constle audit verify` prints it with a "✗ "
// prefix as its verdict on whether an approval was real. A log that carries a
// CR, an ESC or a newline in the fields this line interpolates could erase
// that verdict and redraw it — the line that says an approval does not hold
// up is the last line that should be forgeable by the thing it is judging.
func TestProblemLineEscapesWhatCameOutOfTheLog(t *testing.T) {
	t.Parallel()

	p := DecisionProblem{
		Entry:     3,
		Event:     audit.EventType("gate_approved\r\x1b[2K✓ all decisions verified"),
		RequestID: "hg_dead\nentry 4: gate_approved hg_beef — verified",
		Detail:    "broken\r\x1b[1A✓ nothing to see",
	}
	got := p.String()

	for _, bad := range []struct {
		name string
		s    string
	}{
		{"ESC", "\x1b"}, {"carriage return", "\r"}, {"newline", "\n"},
	} {
		if strings.Contains(got, bad.s) {
			t.Errorf("the problem line still carries a raw %s:\n  %q", bad.name, got)
		}
	}
	if strings.Count(got, "\n") != 0 {
		t.Errorf("the problem line is not one line:\n  %q", got)
	}
	// The escapes must be visible as text, not silently dropped — a dropped
	// byte reads as a log that was clean.
	if !strings.Contains(got, `\u001B`) || !strings.Contains(got, `\u000D`) {
		t.Errorf("control bytes were removed rather than shown:\n  %q", got)
	}
}

// TestProblemLineLeavesOrdinaryTextAlone: the escaping must not change what
// every real verification prints, or it would rewrite the CLI's output for
// every log that is not attacking the operator.
func TestProblemLineLeavesOrdinaryTextAlone(t *testing.T) {
	t.Parallel()

	p := DecisionProblem{
		Entry:     1,
		Event:     audit.EventGateApproved,
		RequestID: "hg_0123456789abcdef",
		Detail:    "records no signed decision at all",
	}
	const want = "entry 1: gate_approved hg_0123456789abcdef — records no signed decision at all"
	if got := p.String(); got != want {
		t.Errorf("ordinary problem line changed:\n  got  %q\n  want %q", got, want)
	}

	// An absent request_id still reads as absent rather than as empty space.
	p.RequestID = ""
	if got := p.String(); !strings.Contains(got, "(no request_id)") {
		t.Errorf("missing request_id is not reported: %q", got)
	}
}

// TestProblemLineBoundsAnOversizedField: the fields come off a file, and a
// file can hold as much as it likes. Bounding after escaping is the point —
// escaping expands, so a cap applied first is not a cap on what is printed.
func TestProblemLineBoundsAnOversizedField(t *testing.T) {
	t.Parallel()

	// Escapes to six printable bytes per input byte, so a cap taken before
	// escaping would let this through at six times its stated size.
	p := DecisionProblem{
		Entry: 2,
		Event: audit.EventType(strings.Repeat("\x00", EvidenceFieldMax)),
	}
	got := p.String()

	if len(got) > 4*EvidenceFieldMax {
		t.Errorf("problem line is %d bytes; the field bound is %d and did not hold",
			len(got), EvidenceFieldMax)
	}
	if !strings.Contains(got, "bytes in all") {
		t.Errorf("a truncated field is not marked as truncated:\n  %q", got)
	}
	if !utf8.ValidString(got) {
		t.Error("truncation split a rune and produced invalid UTF-8")
	}
}

// TestProblemLineTruncationCutsOnARuneBoundary: the cap is a byte count and
// the escaped text is not all single-byte, so the cut has to find a boundary.
func TestProblemLineTruncationCutsOnARuneBoundary(t *testing.T) {
	t.Parallel()

	// Three-byte runes, so the plain byte cut at EvidenceFieldMax lands mid
	// rune unless the boundary search moves it.
	p := DecisionProblem{Entry: 1, Event: audit.EventType(strings.Repeat("ᴀ", EvidenceFieldMax))}
	got := p.String()
	if !utf8.ValidString(got) {
		t.Errorf("truncation produced invalid UTF-8: %q", got)
	}
	if !strings.Contains(got, "bytes in all") {
		t.Errorf("oversized multi-byte field was not bounded: %q", got)
	}
}
