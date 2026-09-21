// Package termsafe escapes untrusted text so that printing it on an
// operator's terminal cannot do anything except put characters on the screen.
//
// constle prints strings it did not write: the sandboxed agent's stdout and
// stderr, every free-form field of an Agentfile the operator may have been
// handed, the DID inside an audit log that travelled here from somewhere
// else, and the reason phrase of an HTTP response from a decision endpoint.
// A single ESC byte in any of those controls the terminal rather than
// appearing on it — it can clear the screen, move the cursor over text
// constle already wrote, open an OSC 8 hyperlink under innocent-looking
// text, write the operator's clipboard with OSC 52, or emit a cursor-position
// query (CSI 6n) whose answer the terminal types back into constle's own
// stdin, ahead of whatever the operator types next.
//
// That last one is why this package exists rather than a narrower fix: the
// human gate asks a question on stdout and reads the answer on stdin, so text
// constle prints is part of the same trust boundary as the decision it
// collects. The guarantee the gate makes — that the bytes shown are the bytes
// signed for — is only as good as constle's ability to keep the screen.
//
// The escaping is lossless and reversible by eye: nothing is elided,
// truncated, or silently dropped, so a hostile byte becomes visible rather
// than invisible. Callers that need a volume limit impose it themselves.
package termsafe

import (
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Line escapes one line of untrusted text. The result is printable runes
// only: it contains no ESC, no other C0 or C1 control byte, no bidi
// override, and no rune that IsPrint rejects.
//
// The rule is one stdlib predicate plus a short list. unicode.IsPrint carries
// almost all of it: a rune Go calls printable prints verbatim, so legitimate
// CJK, accented and emoji text stays readable, and everything else becomes a
// visible ASCII escape. Verified against the whole code space, U+0020 is the
// only rune in the control (Cc), format (Cf — where the bidi overrides and
// zero-width characters live), private-use, surrogate and separator
// categories that IsPrint accepts.
//
// blankButPrintable is the gap IsPrint leaves. A handful of runes are
// categorised as letters or symbols — so IsPrint says yes — yet render as an
// empty cell in every common terminal font: the Hangul fillers and the blank
// Braille pattern. They are indistinguishable from a space on screen, and
// padding a value with them is the cheapest way left to make displayed text
// lie about its own length.
//
// Line treats its input as ONE line: "\n" is not printable, so it is escaped
// like any other control rune rather than passed through. A caller holding
// text whose line structure constle itself wrote wants Block; a caller
// holding raw untrusted bytes wants Lines. Neither may hand a newline to Line
// and expect a line break, which is the point — an untrusted string must not
// be able to invent a line of output.
//
// What this does NOT defend against, stated plainly, because a guarantee
// that overstates itself is worse than a narrow one:
//
//   - Homoglyphs. Cyrillic "раураl.com" is printable, non-blank, and renders
//     as "paypal.com".
//   - Combining marks and variation selectors. U+0301, U+034F COMBINING
//     GRAPHEME JOINER and U+FE0F are all Mn or Cf runes that IsPrint accepts,
//     so they survive: text can be decorated, joined, or stacked into
//     something that reads as other than what it is.
//
// Both are the same shape of problem and neither is a predicate away. Ruling
// them out needs a confusables table and a policy on mixed scripts and mark
// sequences, and banning non-ASCII outright would break the CJK, accented,
// Hebrew and Arabic text this function deliberately keeps readable — those
// scripts are built out of combining marks. What is bounded here is what a
// terminal ACTS on; what a reader can be misled by is bounded by the subject
// digest on the gate prompt, for an operator who has something to compare it
// against.
//
// It decodes rune by rune and so cannot split one; invalid UTF-8 is reported
// a byte at a time as \xNN.
//
// Line is idempotent: its output is printable, so a second pass returns it
// unchanged. Callers may therefore sanitize defensively at more than one
// layer without the escapes compounding.
func Line(s string) string {
	// Fast path: nearly every real string is plain printable text and needs
	// no copy at all. This is also what keeps constle's plain (non-TTY)
	// output byte-for-byte identical for every input that is not hostile.
	needsEscape := false
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) || blankButPrintable(r) {
			needsEscape = true
			break
		}
	}
	if !needsEscape {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// Not valid UTF-8. Show the byte itself; \xNN is not Go or JSON
			// escape syntax, which is the point — it marks a byte that no
			// correct producer of text emits.
			fmt.Fprintf(&b, "\\x%02X", s[i])
		case unicode.IsPrint(r) && !blankButPrintable(r):
			b.WriteRune(r)
		case r > 0xFFFF:
			fmt.Fprintf(&b, "\\U%08X", r)
		default:
			fmt.Fprintf(&b, "\\u%04X", r)
		}
		i += size
	}
	return b.String()
}

// Block escapes multi-line text whose line structure constle itself wrote —
// a composed warning, a formatted error, a prompt. The "\n" separators are
// preserved; everything inside each line goes through Line.
//
// A trailing "\r" on a line is dropped rather than escaped, so text that
// arrived with CRLF endings reads normally. A "\r" anywhere else stays inside
// its line and is escaped, because that is the cursor-to-column-zero
// primitive: left alone it overwrites the line already on screen, which is
// how a gutter, a spine, or a whole warning gets erased and redrawn as
// something else.
//
// KNOWN LIMIT, and the reason this is not the only defence: Block runs after
// formatting, so it cannot tell a "\n" the caller's format string wrote from
// one that arrived inside an interpolated value. It removes every primitive
// that drives the terminal — ESC, the other control bytes, bidi overrides —
// but it does not stop an untrusted value from ending its line and writing a
// line of its own. Where a forged line would be read as constle speaking, the
// untrusted value must go through Line BEFORE it is formatted in; Block is
// the backstop underneath that, not a substitute for it. Args does the first
// half for a printf-style call, and Preformatted marks the arguments whose
// newlines are constle's own.
func Block(s string) string {
	if s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = Line(strings.TrimSuffix(ln, "\r"))
	}
	return strings.Join(lines, "\n")
}

// Lines splits raw untrusted bytes into escaped display lines — the agent's
// own stdout and stderr, where constle wrote none of the structure.
//
// Empty lines INSIDE the stream are kept, so a blank line an agent wrote
// still reads as one and callers decide whether to print it. Leading and
// trailing newlines are trimmed, because the empty lines they produce sit
// outside the output rather than in it.
//
// This is the one path where constle's output is NOT byte-for-byte what it
// was before escaping existed, and the exceptions are worth naming because
// the rest of the project holds that contract exactly:
//
//   - A tab becomes \u0009. It is tempting to expand tabs to spaces instead,
//     since a tab only advances the cursor and cannot erase or colour
//     anything — but doing so needs a column count, and a column count here
//     is wrong three ways at once: it would have to know the width of the
//     runes before it, that escaping has already changed how many columns
//     those runes occupy, and that the caller has drawn a gutter this
//     function cannot see. An 8x expansion of a stream that has deliberately
//     no volume cap is the other half of the reason. One predicate, applied
//     to every control byte alike, is a rule that can be reviewed; a second
//     rule with three inputs it does not have is not.
//   - A "\r\n" pair becomes a line break, so output that arrived with CRLF
//     endings reads normally instead of ending every line in \u000D. A "\r"
//     that no "\n" follows is escaped wherever it sits, last line included:
//     that one is the cursor-to-column-zero primitive, and it is what lets an
//     agent overwrite the gutter and the framing constle drew around its
//     output.
//
// Nothing else is discarded. Leading and trailing whitespace inside the
// stream survives into the escaped output, where a caller that wants to
// suppress a visually empty line can see that it is one.
func Lines(b []byte) []string {
	// CRLF first, and as a pair. Stripping a trailing "\r" per line after
	// the split cannot tell a CRLF ending from a bare carriage return that
	// happens to sit at the end of the last line, so it silently discarded
	// the second one. Collapsing the pair up front makes the distinction
	// exact: what survives to the split is a "\r" that no "\n" followed,
	// which is the cursor-to-column-zero primitive, and it is escaped.
	//
	// Then newlines only — not strings.TrimSpace, which an earlier version
	// used and which also discarded a leading carriage return or a boundary
	// tab before escaping could make either visible. That is the one thing
	// this package promises not to do, and it does not become acceptable
	// because the byte in question was harmless where it sat. Trailing
	// newlines are different: they produce empty lines that carry nothing.
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	s = strings.Trim(s, "\n")
	if s == "" {
		return nil
	}
	out := strings.Split(s, "\n")
	for i, ln := range out {
		out[i] = Line(ln)
	}
	return out
}

// blankButPrintable reports the runes unicode.IsPrint accepts that still
// render as an empty cell. Kept as an explicit list rather than a category
// test because there is no category that holds exactly these: the Hangul
// fillers are Lo (letters) and the blank Braille pattern is So (a symbol).
func blankButPrintable(r rune) bool {
	switch r {
	case 0x115F, // HANGUL CHOSEONG FILLER
		0x1160, // HANGUL JUNGSEONG FILLER
		0x3164, // HANGUL FILLER
		0xFFA0, // HALFWIDTH HANGUL FILLER
		0x2800: // BRAILLE PATTERN BLANK
		return true
	}
	return false
}

// Preformatted marks a string that has already been escaped and whose line
// structure constle itself wrote — a rendered block, a composed prompt. Args
// passes it through untouched instead of escaping its newlines.
//
// It is a distinct named type so that passing one is a deliberate, greppable
// act. A plain string argument is treated as untrusted, which is the right
// default: forgetting to mark trusted text costs a few visible escapes,
// while forgetting to escape untrusted text costs the terminal.
type Preformatted string

func (p Preformatted) String() string { return string(p) }

// Args escapes the untrusted arguments of a printf-style call, returning a new
// slice. Strings and errors go through Line — so an interpolated value cannot
// end its line, move the cursor, or drive the terminal — Preformatted passes
// through, and everything else (numbers, booleans, durations) is left alone.
//
// It is deliberately not recursive: a struct, map, or slice printed with %v
// can still carry untrusted strings inside it, and Args does not reach them.
// Callers that print a composite value hold it to the same rule by hand.
// Whatever Args misses, a Block over the formatted result still strips of
// everything that controls a terminal.
func Args(args []any) []any {
	out := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case Preformatted:
			out[i] = string(v)
		case string:
			out[i] = Line(v)
		case error:
			out[i] = Line(v.Error())
		default:
			out[i] = a
		}
	}
	return out
}

// Fprintf writes one piece of operator-facing text to w with its untrusted
// parts escaped, and is the shape every such writer in this project should
// take. Args runs over the arguments before formatting, so an interpolated
// value cannot end its line and write one that reads as constle speaking;
// Block runs over the result as the backstop for whatever Args does not
// reach. An argument whose newlines are constle's own is passed as
// Preformatted.
//
// The write error is dropped because every caller is already reporting a
// problem on the only channel it has: a failure to write it has nowhere left
// to be reported, and nothing either package decides depends on the text
// having landed.
//
// The reason this exists rather than each package rolling its own: the value
// that reaches a warning like this is usually not a string the caller chose
// but an error it is relaying, and an error's text is assembled far away
// from the print site. *fs.PathError quotes the filename it failed on, and
// in constle that filename is built from an Agentfile's identity.name — so a
// package that never knowingly prints manifest data still does.
func Fprintf(w io.Writer, format string, args ...any) {
	_, _ = io.WriteString(w, Block(fmt.Sprintf(format, Args(args)...)))
}
