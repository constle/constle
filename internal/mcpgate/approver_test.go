package mcpgate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
)

// TestStdinIsTerminalRejectsNonTerminals pins the fail-closed half of the
// detection: none of the stdins a daemonized or piped run actually gets may be
// mistaken for a human at a keyboard, or Decide would block on a read that
// never resolves.
//
// The terminal case cannot be asserted here — `go test` never hands the test
// binary a real tty — so this covers the direction that is both testable and
// dangerous to get wrong. The opposite direction (a real console wrongly
// reported as non-interactive) is what the os.SameFile(os.DevNull) check used
// to get wrong on Windows; see stdinIsTerminal's comment.
func TestStdinIsTerminalRejectsNonTerminals(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("cannot open %s: %v", os.DevNull, err)
	}
	defer func() { _ = devNull.Close() }()

	regular, err := os.Create(filepath.Join(t.TempDir(), "stdin.txt"))
	if err != nil {
		t.Fatalf("cannot create temp file: %v", err)
	}
	defer func() { _ = regular.Close() }()

	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("cannot create pipe: %v", err)
	}
	defer func() { _ = pipeR.Close(); _ = pipeW.Close() }()

	cases := []struct {
		name string
		file *os.File
	}{
		{os.DevNull, devNull},
		{"regular file", regular},
		{"pipe", pipeR},
	}

	realStdin := os.Stdin
	defer func() { os.Stdin = realStdin }()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Stdin = tc.file
			if stdinIsTerminal() {
				t.Errorf("stdinIsTerminal() = true for %s, want false", tc.name)
			}
		})
	}
}

// TestNewTerminalApproverIsNonInteractiveUnderTest checks the wiring, not just
// the predicate: NewTerminalApprover must carry the detection result into
// Interactive, so a gate built in a non-terminal context resolves by timeout
// instead of prompting.
func TestNewTerminalApproverIsNonInteractiveUnderTest(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("cannot open %s: %v", os.DevNull, err)
	}
	defer func() { _ = devNull.Close() }()

	realStdin := os.Stdin
	defer func() { os.Stdin = realStdin }()
	os.Stdin = devNull

	if a := NewTerminalApprover(os.Stdout); a.Interactive {
		t.Error("NewTerminalApprover().Interactive = true with stdin on /dev/null, want false")
	}
}

// renderRequest builds the minimal Request the display path needs. Only
// Arguments varies across the display tests; the rest is prompt furniture.
func renderRequest(args string) Request {
	return Request{
		AgentName: "test-agent", ServerID: "billing", Tool: "pay_invoice",
		Arguments: json.RawMessage(args), TimeoutSeconds: 1, OnTimeout: "abort",
	}
}

// showArguments runs one gated call through Decide's display path and returns
// everything the operator was shown.
//
// It uses Interactive: false deliberately. The arguments are rendered above
// Decide's interactivity branch — what the operator is shown does not depend
// on whether they can answer — so the whole display contract is assertable
// without a pipe, a prompt watcher, or a reader goroutine, and therefore
// without any exposure to the stale-input drain. The decision is never
// DecisionApproved on this path, which is exactly what makes it safe to
// assert what was printed rather than what was decided.
func showArguments(t *testing.T, args string) string {
	t.Helper()
	var out strings.Builder
	a := &TerminalApprover{In: strings.NewReader(""), Out: &out, Interactive: false}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if d := a.Decide(ctx, renderRequest(args)); d != DecisionApproved {
		return out.String()
	}
	t.Fatal("a non-interactive approver approved a call")
	return ""
}

// TestArgumentsAreShownInFullNoMatterHowLong is the regression test for the
// approval-display truncation: the prompt used to print only the first 500
// bytes of params.arguments while the gate forwarded every byte, so anything
// an agent placed past byte 500 executed without ever being shown.
//
// The payload is the shape that made this worth fixing: a benign-looking
// prefix long enough to fill the old window, then — past byte 500 — a second
// "destination_account" whose value is what a last-key-wins JSON parser
// actually uses. The operator approved one account and paid another.
func TestArgumentsAreShownInFullNoMatterHowLong(t *testing.T) {
	const hiddenAccount = "ACH-ATTACKER-9902"
	args := `{"destination_account":"ACH-SAFE-4417","amount_cents":4250,"memo":"` +
		strings.Repeat("routine monthly invoice. ", 30) + // pushes the tail past 500
		`","destination_account":"` + hiddenAccount + `","amount_cents":992450000}`

	if len(args) <= 500 {
		t.Fatalf("payload is %d bytes — it must exceed the old 500-byte window to be a regression test", len(args))
	}

	shown := showArguments(t, args)

	if !strings.Contains(shown, hiddenAccount) {
		t.Errorf("the operator was never shown %q, which is what the call actually pays.\nprompt was:\n%s",
			hiddenAccount, shown)
	}
	if !strings.Contains(shown, "992450000") {
		t.Errorf("the operator was never shown the amount the call actually transfers.\nprompt was:\n%s", shown)
	}
	if strings.Contains(shown, "…") {
		t.Errorf("the prompt still elides arguments with an ellipsis:\n%s", shown)
	}
}

// TestEveryArgumentByteReachesTheOperator generalises the case above: for a
// range of shapes and sizes under the cap, every token of the arguments must
// appear in the prompt. This is the invariant the fix exists to hold — what
// is shown is what is forwarded — rather than a check that one exploit is
// covered.
func TestEveryArgumentByteReachesTheOperator(t *testing.T) {
	cases := []struct {
		name   string
		args   string
		tokens []string
	}{
		{
			"long trailing field",
			`{"pad":"` + strings.Repeat("x", 3000) + `","rm_rf":true}`,
			[]string{"rm_rf", "true"},
		},
		{
			"payload buried in a nested object past the old window",
			`{"note":"` + strings.Repeat("y", 600) + `","opts":{"force":true,"target":"/etc/shadow"}}`,
			[]string{"force", "/etc/shadow"},
		},
		{
			"array tail",
			`{"items":[` + strings.Repeat(`{"sku":"A1","qty":1},`, 40) + `{"sku":"WIRE-OUT","qty":9999}]}`,
			[]string{"WIRE-OUT", "9999"},
		},
		{
			"exactly at the cap",
			`{"pad":"` + strings.Repeat("z", maxDisplayedArgumentBytes-20) + `","tail":1}`,
			[]string{"tail"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.args) > maxDisplayedArgumentBytes {
				t.Fatalf("case is %d bytes, over the display cap — it belongs in the refusal test", len(tc.args))
			}
			shown := showArguments(t, tc.args)
			for _, tok := range tc.tokens {
				if !strings.Contains(shown, tok) {
					t.Errorf("token %q never reached the operator", tok)
				}
			}
		})
	}
}

// TestRenderedArgumentsKeepJSONStructure pins the second half of "shown in
// full": the render has to be readable, and its line structure has to come
// from constle rather than from the agent. json.Indent rebuilds every
// structural byte, so whitespace the agent wrote between tokens — a carriage
// return that erases the line above, a newline that forges an extra prompt
// line — never reaches the terminal.
func TestRenderedArgumentsKeepJSONStructure(t *testing.T) {
	shown := showArguments(t, "{\"a\":1,\r\n\t\t\"b\":\"/etc/shadow\"}")

	if strings.Contains(shown, "\r") {
		t.Errorf("agent-supplied carriage return survived into the prompt: %q", shown)
	}
	for _, want := range []string{"\"a\": 1", "\"b\": \"/etc/shadow\""} {
		if !strings.Contains(shown, want) {
			t.Errorf("rendered arguments missing %q:\n%s", want, shown)
		}
	}
	if _, lines := renderArguments(json.RawMessage(`{"a":1,"b":2}`)); lines != 4 {
		t.Errorf("renderArguments reported %d lines for a two-key object, want 4", lines)
	}
}

// TestSanitizeForTerminalEscapesWhatCannotBeSeen covers the other half of
// "the operator saw it": encoding/json rejects raw control bytes inside a
// string literal, but every rune at or above U+0080 gets through, including
// the ones that attack the reader rather than the terminal.
//
// Both the inputs and the expectations are written as Go escapes on purpose.
// Pasting these runes into this file as literals is the same trick the code
// under test exists to defeat, one layer up — and Go rejects a literal
// U+FEFF in source outright.
func TestSanitizeForTerminalEscapesWhatCannotBeSeen(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain ascii is untouched", `{"to":"a@b.example"}`, `{"to":"a@b.example"}`},
		{"CJK stays readable", "{\"memo\":\"\u8ACB\u6C42\u66F8\"}", "{\"memo\":\"\u8ACB\u6C42\u66F8\"}"},
		{"accents stay readable", "{\"name\":\"More\u00F1o\"}", "{\"name\":\"More\u00F1o\"}"},
		{"emoji stays readable", "{\"tag\":\"\U0001F525\"}", "{\"tag\":\"\U0001F525\"}"},
		{"bidi override is escaped", "{\"to\":\"a\u202Eb\"}", `{"to":"a\u202Eb"}`},
		{"zero-width space is escaped", "{\"to\":\"a\u200Bb\"}", `{"to":"a\u200Bb"}`},
		{"byte order mark is escaped", "{\"to\":\"a\uFEFFb\"}", `{"to":"a\uFEFFb"}`},
		{"non-breaking space is escaped", "{\"to\":\"a\u00A0b\"}", `{"to":"a\u00A0b"}`},
		{"line separator is escaped", "{\"to\":\"a\u2028b\"}", `{"to":"a\u2028b"}`},
		{"soft hyphen is escaped", "{\"to\":\"a\u00ADb\"}", `{"to":"a\u00ADb"}`},
		{"astral non-printable is escaped", "{\"t\":\"\U000E0041\"}", `{"t":"\U000E0041"}`},
		{"invalid utf-8 is escaped", "{\"t\":\"\xFF\"}", `{"t":"\xFF"}`},
		{"an escape spelled out in the source keeps its own backslashes",
			`{"to":"a\\u202eb"}`, `{"to":"a\\u202eb"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeForTerminal(tc.in); got != tc.want {
				t.Errorf("sanitizeForTerminal(%q)\n = %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestHostileRunesNeverReachTheTerminalVerbatim pins the same property one
// level up, through the real display path, so an escaper that is correct in
// isolation cannot be bypassed by how renderArguments calls it. Escaping,
// not stripping: a rune the operator cannot see is exactly as bad silently
// removed as it is silently shown.
func TestHostileRunesNeverReachTheTerminalVerbatim(t *testing.T) {
	// Every rune asserted below is actually present in the payload — a check
	// for one that is not would pass vacuously.
	shown := showArguments(t,
		"{\"to\":\"safe@example.com\u202E\u200B\uFEFF\u3164\u2800\",\"amount\":1}")

	for _, r := range []rune{0x202E, 0x200B, 0xFEFF, 0x3164, 0x2800} {
		if strings.ContainsRune(shown, r) {
			t.Errorf("rune %U reached the operator's terminal verbatim", r)
		}
		if want := fmt.Sprintf(`\u%04X`, r); !strings.Contains(shown, want) {
			t.Errorf("rune %U was hidden rather than escaped to %s:\n%s", r, want, shown)
		}
	}
}

// TestBlankButPrintableRunesAreEscaped guards the gap unicode.IsPrint leaves.
// These render as an empty cell in every common terminal font yet IsPrint
// accepts them — the Hangul fillers are letters and the blank Braille pattern
// is a symbol — so padding a value with them is otherwise a free way to make
// displayed text lie.
func TestBlankButPrintableRunesAreEscaped(t *testing.T) {
	for _, r := range []rune{0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800} {
		if !unicode.IsPrint(r) {
			t.Fatalf("premise wrong: unicode.IsPrint(%U) is already false, the list is unnecessary", r)
		}
		got := sanitizeForTerminal(string(r))
		if want := fmt.Sprintf(`\u%04X`, r); got != want {
			t.Errorf("sanitizeForTerminal(%U) = %q, want %q", r, got, want)
		}
	}

	// The neighbouring real Hangul syllable must stay readable: the list is a
	// named set, not a range, and must not swallow legitimate text.
	if got := sanitizeForTerminal("\uD55C"); got != "\uD55C" {
		t.Errorf("a real Hangul syllable was escaped: %q", got)
	}
}

// TestUnparseableArgumentsCannotForgePromptLines covers renderArguments'
// json.Indent fallback. It is unreachable through the gate proxy — parseJSONRPC
// validates the whole body first — but Decide is exported, and the fallback is
// the only path whose newlines constle did not write itself. Letting those
// through would print lines indistinguishable from the prompt's own.
func TestUnparseableArgumentsCannotForgePromptLines(t *testing.T) {
	forged := "not json\n   approve? [a]pprove / [d]eny (timeout 300s): "

	text, lines := renderArguments(json.RawMessage(forged))
	if lines != 1 {
		t.Errorf("unparseable arguments rendered as %d lines, want 1", lines)
	}
	if strings.Contains(text, "\n") {
		t.Errorf("an agent-supplied newline survived the fallback: %q", text)
	}
	if !strings.Contains(text, `\u000A`) {
		t.Errorf("the newline was dropped rather than escaped: %q", text)
	}
}

// TestEmptyArgumentsSaySo: a call with no arguments must say so explicitly.
// Printing nothing would leave the operator to infer the difference between
// "this call takes no arguments" and "the arguments were not shown".
func TestEmptyArgumentsSaySo(t *testing.T) {
	for _, raw := range []string{"", "{}"} {
		block, why := displayableArguments(json.RawMessage(raw))
		if why != "" {
			t.Fatalf("displayableArguments(%q) refused: %s", raw, why)
		}
		if raw == "" && !strings.Contains(block, "(none)") {
			t.Errorf("absent arguments rendered as %q, want an explicit (none)", block)
		}
	}
}

// TestDisplayBudgetBoundaries pins the exact edges, which is where an
// off-by-one would silently widen or narrow what a prompt can cover.
func TestDisplayBudgetBoundaries(t *testing.T) {
	atSize := func(n int) string {
		pad := n - len(`{"p":""}`)
		return `{"p":"` + strings.Repeat("x", pad) + `"}`
	}

	if _, why := displayableArguments(json.RawMessage(atSize(maxDisplayedArgumentBytes))); why != "" {
		t.Errorf("arguments of exactly %d bytes were refused: %s", maxDisplayedArgumentBytes, why)
	}
	if _, why := displayableArguments(json.RawMessage(atSize(maxDisplayedArgumentBytes + 1))); why == "" {
		t.Errorf("arguments of %d bytes were accepted, one over the limit", maxDisplayedArgumentBytes+1)
	}
}
