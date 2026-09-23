package termsafe

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// TestLineEscapesWhatCannotBeSeen is the core table. It covers both halves of
// "the operator saw it": the control bytes that drive a terminal, and the
// runes at or above U+0080 that attack the reader rather than the terminal.
//
// Both the inputs and the expectations are written as Go escapes on purpose.
// Pasting these runes into this file as literals is the same trick the code
// under test exists to defeat, one layer up — and Go rejects a literal U+FEFF
// in source outright.
func TestLineEscapesWhatCannotBeSeen(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain ascii is untouched", `{"to":"a@b.example"}`, `{"to":"a@b.example"}`},
		{"CJK stays readable", "{\"memo\":\"請求書\"}", "{\"memo\":\"請求書\"}"},
		{"accents stay readable", "{\"name\":\"Moreño\"}", "{\"name\":\"Moreño\"}"},
		{"emoji stays readable", "{\"tag\":\"\U0001F525\"}", "{\"tag\":\"\U0001F525\"}"},
		{"ESC is escaped", "a\x1bb", `a\u001Bb`},
		{"a CSI clear-screen is escaped", "\x1b[2J\x1b[H", `\u001B[2J\u001B[H`},
		{"a cursor-position query is escaped", "\x1b[6n", `\u001B[6n`},
		{"an OSC 52 clipboard write is escaped", "\x1b]52;c;aGk=\x07", `\u001B]52;c;aGk=\u0007`},
		{"a carriage return is escaped", "safe\rforged", `safe\u000Dforged`},
		{"a newline is escaped, not honoured", "one\ntwo", `one\u000Atwo`},
		{"a tab is escaped", "a\tb", `a\u0009b`},
		{"a C1 control byte is escaped", "a\u009Bb", `a\u009Bb`},
		{"bidi override is escaped", "{\"to\":\"a\u202Eb\"}", `{"to":"a\u202Eb"}`},
		{"zero-width space is escaped", "{\"to\":\"a\u200Bb\"}", `{"to":"a\u200Bb"}`},
		{"byte order mark is escaped", "{\"to\":\"a\uFEFFb\"}", `{"to":"a\uFEFFb"}`},
		{"non-breaking space is escaped", "{\"to\":\"a\u00A0b\"}", `{"to":"a\u00A0b"}`},
		{"line separator is escaped", "{\"to\":\"a\u2028b\"}", `{"to":"a\u2028b"}`},
		{"soft hyphen is escaped", "{\"to\":\"a\u00ADb\"}", `{"to":"a\u00ADb"}`},
		{"astral non-printable is escaped", "{\"t\":\"\U000E0041\"}", `{"t":"\U000E0041"}`},
		{"invalid utf-8 is escaped", "{\"t\":\"\xFF\"}", `{"t":"\xFF"}`},
		{"a lone surrogate byte sequence is escaped", "a\xed\xa0\x80b", `a\xED\xA0\x80b`},
		{"an escape spelled out in the source keeps its own backslashes",
			`{"to":"a\\u202eb"}`, `{"to":"a\\u202eb"}`},
		{"empty stays empty", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Line(tc.in); got != tc.want {
				t.Errorf("Line(%q)\n = %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestLineIsIdempotent matters because the fix sanitizes defensively at more
// than one layer — a chokepoint and the call site feeding it. If a second
// pass escaped the backslashes of the first, depth would corrupt the display
// instead of protecting it.
func TestLineIsIdempotent(t *testing.T) {
	for _, in := range []string{
		"\x1b[2J", "a\u202Eb", "\xFF\xFE", "plain text", "\U0001F525", "a\tb\nc\r",
	} {
		once := Line(in)
		if twice := Line(once); twice != once {
			t.Errorf("Line is not idempotent for %q: %q then %q", in, once, twice)
		}
	}
}

// TestBlankButPrintableRunesAreEscaped guards the gap unicode.IsPrint leaves.
// These render as an empty cell in every common terminal font yet IsPrint
// accepts them — the Hangul fillers are letters and the blank Braille pattern
// is a symbol — so padding a value with them is otherwise a free way to make
// displayed text lie about its own length.
func TestBlankButPrintableRunesAreEscaped(t *testing.T) {
	for _, r := range []rune{0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800} {
		if !unicode.IsPrint(r) {
			t.Fatalf("premise wrong: unicode.IsPrint(%U) is already false, the list is unnecessary", r)
		}
		got := Line(string(r))
		if want := fmt.Sprintf(`\u%04X`, r); got != want {
			t.Errorf("Line(%U) = %q, want %q", r, got, want)
		}
	}

	// The neighbouring real Hangul syllable must stay readable: the list is a
	// named set, not a range, and must not swallow legitimate text.
	if got := Line("한"); got != "한" {
		t.Errorf("a real Hangul syllable was escaped: %q", got)
	}
}

// TestLineKeepsBenignTextByteIdentical is the compatibility contract. constle's
// non-TTY output is asserted byte-for-byte by its E2E tests and consumed by
// scripts, so sanitizing unconditionally is only acceptable if it is a no-op
// for everything that is not hostile.
func TestLineKeepsBenignTextByteIdentical(t *testing.T) {
	for _, in := range []string{
		"", " ", "agent-name", "v1.2.3", "ghcr.io/org/image:tag",
		"~/.constle/logs/invoice-agent-2026-09-21.jsonl",
		"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		"  ┌─ agent output ──────────────────────────",
		"⚠️  warning: some human_gates entries are NOT enforced:",
		"請求書 Moreño \U0001F525",
	} {
		if got := Line(in); got != in {
			t.Errorf("benign text was rewritten: Line(%q) = %q", in, got)
		}
	}
}

func TestBlockKeepsTheLinesConstleWrote(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"newlines constle wrote survive", "error: bad\n  detail\n", "error: bad\n  detail\n"},
		{"CRLF endings normalise", "one\r\ntwo\r\n", "one\ntwo\n"},
		{"a lone CR is escaped, not turned into a break",
			"warning: gates NOT enforced\rgates enforced", `warning: gates NOT enforced\u000Dgates enforced`},
		{"ESC inside a line is escaped", "error: \x1b[2Jgone\n", `error: \u001B[2Jgone` + "\n"},
		{"empty stays empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Block(tc.in); got != tc.want {
				t.Errorf("Block(%q)\n = %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestLineIsWhatStopsAForgedLine pins the division of labour between the two
// entry points, because getting it backwards is how this bug returns.
//
// An untrusted value spliced into a line constle composed must not be able to
// end that line and write one of its own — here, turning the warning that a
// gate is NOT enforced into a line claiming it is. Line does that, because it
// runs on the value before it is formatted in. Block cannot: by the time it
// sees the text, the injected newline and the caller's own are the same byte.
func TestLineIsWhatStopsAForgedLine(t *testing.T) {
	hostile := "send_email\n   enforced: send_email  ∙  at gate"

	safe := "   and will run WITHOUT approval: " + Line(hostile) + "\n"
	if strings.Count(safe, "\n") != 1 {
		t.Errorf("Line let an untrusted value add a line: %q", safe)
	}
	if strings.Contains(safe, "\n   enforced:") {
		t.Errorf("a forged line reached the operator: %q", safe)
	}

	// The documented limit, asserted so that it stays a decision rather than
	// becoming a surprise: Block alone does NOT close this.
	late := Block("   and will run WITHOUT approval: " + hostile + "\n")
	if !strings.Contains(late, "\n   enforced:") {
		t.Error("Block now collapses interpolated newlines — update its doc comment " +
			"and the callers that rely on Line running first")
	}

	// What Block does guarantee, on the same input: nothing that drives the
	// terminal survives.
	for _, r := range []rune{0x1B, 0x0D} {
		if strings.ContainsRune(Block("x\x1b[2Jy\rz\n"), r) {
			t.Errorf("Block let %U through", r)
		}
	}
}

func TestLinesSplitsUntrustedOutput(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"plain output is unchanged", "one\ntwo\nthree", []string{"one", "two", "three"}},
		{"trailing newline does not add a line", "one\ntwo\n", []string{"one", "two"}},
		{"CRLF endings normalise", "one\r\ntwo\r\n", []string{"one", "two"}},
		{"newline-only output yields no lines", "\n\n", nil},
		{"boundary whitespace survives instead of vanishing", "  indented  ", []string{"  indented  "}},
		{"a leading CR is escaped, not discarded", "\rsafe", []string{`\u000Dsafe`}},
		{"a bare trailing CR is escaped, not discarded", "safe\r", []string{`safe\u000D`}},
		{"a lone CR is a line, not nothing", "\r", []string{`\u000D`}},
		{"CRLF is a line break even on the last line", "a\r\nb\r\n", []string{"a", "b"}},
		{"a CR not followed by LF stays, next to one that is", "a\r\rb\r\nc", []string{`a\u000D\u000Db`, "c"}},
		{"a boundary tab is escaped, not discarded", "\tsafe", []string{`\u0009safe`}},
		{"a lone CR cannot erase the gutter", "safe\rforged", []string{`safe\u000Dforged`}},
		{"a CSI clear is escaped", "before\n\x1b[2J\x1b[Hafter", []string{"before", `\u001B[2J\u001B[Hafter`}},
		{"blank interior lines are kept", "one\n\ntwo", []string{"one", "", "two"}},
		{"a tab is escaped like every other control byte", "a\tb", []string{`a\u0009b`}},
		{"invalid utf-8 is escaped", "a\xFFb", []string{`a\xFFb`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Lines([]byte(tc.in))
			if len(got) != len(tc.want) {
				t.Fatalf("Lines(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("Lines(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestLinesKeepsBenignLineStructure pins what a well-behaved agent's output
// looks like, which is the compatibility half of Lines' contract: the fix
// must not change how ordinary output renders.
//
// It deliberately does NOT assert the old strings.TrimSpace behaviour. That
// implementation also discarded a leading carriage return and a boundary tab
// before anything could escape them, which is the one thing this package
// promises not to do; the cases above pin the replacement.
func TestLinesKeepsBenignLineStructure(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"hello\n", []string{"hello"}},
		{"a\nb\nc", []string{"a", "b", "c"}},
		{"\n\nhello\n\n", []string{"hello"}},
		{"", nil},
		{"single line no newline", []string{"single line no newline"}},
		{"one\n\ntwo\n", []string{"one", "", "two"}},
	} {
		got := Lines([]byte(tc.in))
		if len(got) != len(tc.want) {
			t.Fatalf("Lines(%q) = %q, want %q", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("Lines(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}
