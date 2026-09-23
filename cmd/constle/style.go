package main

// ============================================================
// style.go — TTY-gated visual styling for the constle CLI.
//
// DESIGN INVARIANT (non-negotiable): every styled write in this package is
// gated on `styled`, which is true only when os.Stdout is a real terminal.
// When stdout is a pipe, a file, /dev/null, Windows NUL, or a captured
// bytes.Buffer (exactly how every E2E test observes output), `styled` is
// false and callers emit byte-for-byte the plain text they always have.
//
// This mirrors the principle already used for stdin in
// internal/mcpgate/approver.go's stdinIsTerminal(): detect a real terminal
// and gate behaviour on it. We use mattn/go-isatty (a transitive lipgloss
// dependency) rather than a hand-rolled os.Stat/SameFile check because it is
// correct on Windows too — GetConsoleMode there, ioctl on unix — which the
// SameFile(NUL) approach is not (a real console and NUL are both
// FILE_TYPE_CHAR with identical zero SameFile identity).
//
// Construction is provably silent: importing lipgloss/termenv and building a
// renderer only reads env vars + one read-only isatty syscall; no bytes and
// no terminal query escape sequences are ever written at construction. The
// OSC/CSI query paths live solely behind HasDarkBackground/BackgroundColor,
// which this package never calls (no AdaptiveColor, no WithColorCache).
//
// DESIGN LANGUAGE: flagship-CLI restraint (Claude Code / Vercel / gh / Stripe).
// Quiet almost everywhere — aligned rows, dim labels, one accent — and bold at
// exactly one moment: the run outcome, rendered as a solid high-contrast pill
// that stays visible on any dark terminal theme. No full-width boxes: a
// near-navy fill is invisible against a typical near-black terminal, so fills
// are used only where they carry high contrast (the pill).
// ============================================================

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/mattn/go-runewidth"

	"github.com/constle/constle/internal/termsafe"
)

// Palette. Brand anchors (Lavender/Green/Orange/Navy/SoftGray) with two
// legibility-driven tints added for terminal body text, chosen by rendering
// and looking — not by hex in isolation:
//   - colMuted  replaces raw Slate (#485563) for labels: slate is too dark to
//     read as body text on a near-black terminal.
//   - colAccent lightens Lavender for foreground text; colAccentFill keeps the
//     brand #6366F1 for solid fills.
//
// TODO(brand): colDanger is a PLACEHOLDER (Tailwind red-500). Replace with the
// exact brand danger/error red once the brand guide pins a value.
//
// colDanger is deliberately used ONLY as the failure pill's fill (see pill).
// It has no foreground-text style, because the design language above puts
// every warning in amber and reserves red for that single filled moment; and
// the obvious other candidate — die()'s message — writes to stderr, which
// `styled` (a check on stdout) is the wrong gate for. Restore a text style
// here only alongside a real caller.
const (
	colInk        = "#F3F4F6" // primary text (brand Soft Gray)
	colMuted      = "#8B95A5" // secondary text / labels (readable dim)
	colFaint      = "#4A5160" // faint: rules, the │ gutter, de-emphasis
	colAccent     = "#8B8FF5" // lavender tint for foreground accents
	colAccentFill = "#6366F1" // brand Lavender, for solid fills
	colGreen      = "#22C55E" // success
	colAmber      = "#F59E0B" // warning (brand Orange)
	colDanger     = "#EF4444" // PLACEHOLDER — see TODO above
	colOnFill     = "#0B0E14" // near-black text on light-ish pills (green/amber)
)

// styled reports whether stdout is a real terminal we should style. It is the
// single gate for every visual effect in this package.
var styled = detectStyled()

func detectStyled() bool {
	// Honour the de-facto standards for suppressing colour.
	if noColorRequested() || os.Getenv("TERM") == "dumb" {
		return false
	}
	fd := os.Stdout.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// NO_COLOR is presence-based: even an explicitly empty value requests plain
// output. LookupEnv preserves that distinction; Getenv does not.
func noColorRequested() bool {
	_, present := os.LookupEnv("NO_COLOR")
	return present
}

// Lazily-built styles. Only constructed on the styled path (initStyles),
// so no lipgloss work happens at all when output is plain.
var (
	styleOnce sync.Once
	rndr      *lipgloss.Renderer

	stWord   lipgloss.Style // wordmark
	stVer    lipgloss.Style // version / faint meta
	stMuted  lipgloss.Style // labels, secondary
	stInk    lipgloss.Style // primary values
	stAccent lipgloss.Style // accent text (spinner, marks)
	stGreen  lipgloss.Style
	stAmber  lipgloss.Style
	// No stDanger: the palette's danger red is a FILL, never foreground text
	// — see colDanger's note. pill() applies it directly as a background, so
	// a red text style would have no caller.
	stMark    lipgloss.Style // mascot mark (help screen only)
	stAgtHead lipgloss.Style // AGENT OUTPUT heading (accent, bold)
	stSpine   lipgloss.Style // the ▎ accent spine beside agent output
)

func initStyles() {
	styleOnce.Do(func() {
		rndr = lipgloss.NewRenderer(os.Stdout)
		c := func(h string) lipgloss.Color { return lipgloss.Color(h) }

		stWord = rndr.NewStyle().Bold(true).Foreground(c(colInk))
		stVer = rndr.NewStyle().Foreground(colorFaint())
		stMuted = rndr.NewStyle().Foreground(c(colMuted))
		stInk = rndr.NewStyle().Foreground(c(colInk))
		stAccent = rndr.NewStyle().Foreground(c(colAccent))
		stGreen = rndr.NewStyle().Foreground(c(colGreen))
		stAmber = rndr.NewStyle().Foreground(c(colAmber))
		stMark = rndr.NewStyle().Foreground(c(colAccent))
		stAgtHead = rndr.NewStyle().Bold(true).Foreground(c(colAccent))
		stSpine = rndr.NewStyle().Foreground(c(colAccent))
	})
}

func colorFaint() lipgloss.Color { return lipgloss.Color(colFaint) }

const indent = "  " // every styled block shares a 2-space left margin

// ------------------------------------------------------------
// Header — a clean wordmark + dim meta, no mark
// ------------------------------------------------------------

// printHeader renders the per-run header (styled) or today's exact plain line.
//
// The Warden mascot is deliberately NOT drawn here. As a small block glyph it
// reads as an ambiguous diamond/hive rather than the intended keyhole/shield,
// and a mark that doesn't parse at a glance hurts the premium feel more than a
// plain wordmark. The brand's mark direction (a "C" monogram vs. the Warden)
// is also still undecided, so no iteration is sunk into it here. The header is
// kept to a bold wordmark over one dim meta line — hierarchy through weight and
// brightness, one accent used sparingly (the taste reference). The mascot
// survives only as a one-time reveal in `constle help` (itself flagged to
// revisit once brand direction is final).
func printHeader() {
	if !styled {
		printf("\nconstle v%s\n\n", constleVersion)
		return
	}
	initStyles()
	printf("\n%s%s\n", indent, stWord.Render("constle"))
	printf("%s%s\n\n", indent, stVer.Render("v"+constleVersion+"  ∙  agent runtime"))
}

// printStyledHelp renders the help/startup screen (TTY only): the Warden, the
// brand lockup, and an aligned command list. The plain path in printHelp stays
// byte-identical.
func printStyledHelp() {
	initStyles()
	printf("\n")
	printBigMascot()
	printf("\n%s%s %s\n\n", indent, stWord.Render("constle"),
		stVer.Render("v"+constleVersion+"  ∙  AI agent runtime"))
	printStyledHelpBody()
}

// printPostIntroHelp follows the persistent settled lockup emitted during the
// alternate-screen handoff with the useful part of the help screen.
func printPostIntroHelp() {
	if !styled {
		return
	}
	initStyles()
	printStyledHelpBody()
}

// printStyledHelpBody renders the shared usage, command list, and docs link.
// It deliberately owns all spacing inside that block so the explicit styled
// help screen remains visually identical when the block is reused.
func printStyledHelpBody() {
	initStyles()
	printf("%s%s %s\n\n", indent, stMuted.Render("usage"),
		stVer.Render("constle [--no-animation] [command] [args]"))

	cmds := [][2]string{
		{"init", "create agent.yaml with sensible defaults"},
		{"run <agentfile>", "run an agent in a sandbox"},
		{"validate <agentfile>", "check if an Agentfile is valid"},
		{"identity create <name>", "create a cryptographic identity (did:key)"},
		{"identity show <name>", "show an agent's DID and key location"},
		{"webhook-keygen <name>", "generate a human-gates approver keypair (did:key)"},
		{"audit verify <logfile>", "verify a signed audit log and its gate decisions"},
		{"ps", "list running and recent agents"},
		{"stop <run_id>", "stop a running agent by run ID"},
		{"version", "show version"},
	}
	w := 0
	for _, c := range cmds {
		if len(c[0]) > w {
			w = len(c[0])
		}
	}
	for _, c := range cmds {
		verb, rest := c[0], ""
		if i := strings.IndexByte(c[0], ' '); i >= 0 {
			verb, rest = c[0][:i], c[0][i:]
		}
		cmd := stAccent.Render(verb) + stVer.Render(rest)
		pad := strings.Repeat(" ", w-len(c[0]))
		printf("%s  %s%s   %s\n", indent, cmd, pad, stMuted.Render(c[1]))
	}
	printf("\n%s%s  %s\n\n", indent, stMuted.Render("docs"), stAccent.Render("https://constle.dev"))
}

// printBigMascot prints a larger Warden for the `constle help` screen only — a
// one-time reveal, never rendered on every run (see printHeader).
//
// TODO(brand): revisit even this placement once the brand's mark direction is
// settled (a "C" monogram vs. the Warden). If the Warden is not chosen, drop
// this too; if it is, replace this block art with the finalized mark.
func printBigMascot() {
	if !styled {
		return
	}
	initStyles()
	// A shield with a keyhole — the Warden that guards the sandbox.
	art := []string{
		"▟██████▙",
		"███▄▄███",
		"███▘▝███",
		"████████",
		"▜██████▛",
		" ▜████▛",
		"  ▜██▛",
	}
	for _, ln := range art {
		printf("%s%s\n", indent, stMark.Render(ln))
	}
}

// ------------------------------------------------------------
// Run summary — aligned dim-label / bright-value rows, no box
// ------------------------------------------------------------

type kv struct {
	label string
	value string
}

// renderSummaryRows prints label/value rows with a dynamically-aligned label
// column. Values are already composed by the caller (may contain accents).
func renderSummaryRows(rows []kv) {
	initStyles()
	w := 0
	for _, r := range rows {
		if n := runewidth.StringWidth(r.label); n > w {
			w = n
		}
	}
	for _, r := range rows {
		label := stMuted.Render(padr(r.label, w))
		printf("%s%s   %s\n", indent, label, r.value)
	}
}

// subject prints the focal identity line (agent name + version).
//
// Both values come straight out of an Agentfile, which the operator may have
// been handed rather than written: identity.name is checked only for path
// separators and identity.version is not checked at all, so neither is
// trustworthy text. They are escaped here rather than at each caller because
// every caller passes raw manifest fields — there is no version of this line
// that wants anything else.
func subjectLine(name, version string) {
	initStyles()
	printf("%s%s %s\n", indent,
		stWord.Render(termsafe.Line(name)), stVer.Render("v"+termsafe.Line(version)))
}

// ------------------------------------------------------------
// Agent output — the most important content on screen, so it gets real
// presence: a bold accent heading over an accent spine. Not a filled box —
// that would fight the outcome pill (the one deliberate fill). Weight and one
// accent colour carry the hierarchy instead.
// ------------------------------------------------------------

func renderAgentOutput(caption string, lines []string) {
	initStyles()
	printf("%s%s\n", indent, stAgtHead.Render(strings.ToUpper(caption)))
	bar := stSpine.Render("▎")
	if len(lines) == 0 {
		printf("%s%s %s\n", indent, bar, stMuted.Render("(no output)"))
		return
	}
	for _, ln := range lines {
		// Defence in depth: cmdRun already builds these with termsafe.Lines.
		// Escaping again costs nothing (termsafe.Line is idempotent) and
		// means this renderer is safe for any caller, not only that one.
		printf("%s%s %s\n", indent, bar, stInk.Render(termsafe.Line(ln)))
	}
}

// ------------------------------------------------------------
// Final status — the one bold moment: a solid filled pill
// ------------------------------------------------------------

type statusKind int

const (
	stKindOK statusKind = iota
	stKindFail
	stKindStop
)

func pill(label string, kind statusKind) string {
	initStyles()
	var bg, fg lipgloss.Color
	switch kind {
	case stKindOK:
		bg, fg = lipgloss.Color(colGreen), lipgloss.Color(colOnFill)
	case stKindStop:
		bg, fg = lipgloss.Color(colAmber), lipgloss.Color(colOnFill)
	default:
		bg, fg = lipgloss.Color(colDanger), lipgloss.Color(colInk)
	}
	return rndr.NewStyle().Background(bg).Foreground(fg).Bold(true).
		Padding(0, 1).Render(label)
}

// ------------------------------------------------------------
// Warnings — restrained amber, one marker, aligned continuation
// ------------------------------------------------------------

func warnBlock(w io.Writer, lines []string) {
	// Every warning block in this package interpolates an Agentfile field it
	// cannot vouch for — the require_approval_for entries that are NOT
	// enforced, the agent name behind an unusable identity.did. Escaping
	// happens here, once, on plain text that no caller has styled yet, which
	// is also what stops a value from ending its line and writing one that
	// reads as constle's own. The warning whose text an injected line would
	// overwrite is literally "will run WITHOUT approval".
	lines = append([]string(nil), lines...)
	for i, ln := range lines {
		lines[i] = termsafe.Line(ln)
	}

	if !styled || !isStdout(w) {
		for _, ln := range lines {
			fprintln(w, ln)
		}
		fprintln(w)
		return
	}
	initStyles()
	// lines[0] is the headline (may start with the plain "⚠️  warning:"
	// prefix); the rest are continuation detail. Restyle without emoji.
	head := stripWarnPrefix(lines[0])
	fprintf(w, "%s%s %s\n", indent, stAmber.Bold(true).Render("!"), stAmber.Render(head))
	for _, ln := range lines[1:] {
		fprintf(w, "%s  %s\n", indent, stMuted.Render(strings.TrimLeft(ln, " ")))
	}
	fprintln(w)
}

// fprintf and fprintln write operator-facing text to a caller-supplied
// writer — stdout in production, a capture buffer in tests.
//
// Their errors are dropped, deliberately and in one place rather than at
// every call site: this writer is the channel constle reports problems on,
// so a write that fails has nowhere left to report itself, and nothing the
// CLI decides depends on the text having landed. Writes that DO carry a
// consequence (the audit log, the spending ledger) go through their own
// packages, never through here.
func fprintf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func fprintln(w io.Writer, args ...any) {
	_, _ = fmt.Fprintln(w, args...)
}

// stripWarnPrefix removes the plain "⚠️  warning:" lead-in so the styled
// version can present its own marker. Non-styled output keeps the original.
func stripWarnPrefix(s string) string {
	s = strings.TrimLeft(s, " ")
	for _, p := range []string{"⚠️  warning: ", "⚠️ warning: ", "warning: "} {
		if strings.HasPrefix(s, p) {
			return strings.TrimPrefix(s, p)
		}
	}
	return s
}

func isStdout(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && f == os.Stdout
}

// shortID abbreviates a run_id for the dim footer / settled setup line. The
// full id stays in the audit log; here it is only a glanceable handle.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return id
}

// ------------------------------------------------------------
// Setup phase — collapse the pre-run steps to a single settled line.
//
// Density (the live-view review): steps that finish successfully should not
// each occupy a permanent row and grow into a block. In styled mode the whole
// setup sequence (detect backend → prepare identity/gates → start sandbox)
// overwrites ONE spinner line and only settle() leaves a permanent ✓ — the
// npm-install / docker-compose-up / cargo-build convention. Full history is
// still available via the terminal's own scrollback; nothing is built for that.
//
// In non-styled mode every method delegates to the exact printStep/printOK/
// printf calls constle has always emitted, so piped/captured output (every
// E2E test) stays byte-for-byte identical.
// ------------------------------------------------------------

type setup struct{ sp *spinner }

func newSetup() *setup { return &setup{} }

// step announces the current activity: a fresh or updated collapsing line
// (styled) or a plain "  → msg" step (non-styled).
func (s *setup) step(format string, a ...any) {
	if !styled {
		printStep(format, a...)
		return
	}
	if s.sp == nil {
		s.sp = startSpinner(format, a...)
	} else {
		s.sp.set(format, a...)
	}
}

// ok records a sub-step success. Styled: intentionally transient — it folds
// into the collapsing line, which the next step()/settle() overwrites, so no
// permanent row accrues. Non-styled: the usual permanent "  ✓ msg" line.
func (s *setup) ok(format string, a ...any) {
	if !styled {
		printOK(format, a...)
	}
}

// gap emits the blank separator the plain output carries between setup groups.
// Styled collapses, so it has no gap.
func (s *setup) gap() {
	if !styled {
		printf("\n")
	}
}

// fail abandons the collapsing line so a returned error reads cleanly. Safe to
// defer: after settle() the spinner is inactive and this is a no-op.
func (s *setup) fail() {
	if styled && s.sp != nil {
		s.sp.stopClear()
	}
}

// settle finishes the phase with one permanent line. styledLine is the settled
// styled text (rendered as "✓ <styledLine>"); plainFormat/a reproduce the
// exact plain line the sandbox spinner used to print.
func (s *setup) settle(styledLine, plainFormat string, a ...any) {
	if styled {
		if s.sp != nil {
			s.sp.ok("%s", styledLine)
		}
		return
	}
	printOK(plainFormat, a...)
}

// prettyPath abbreviates the invoking user's home dir to ~ for display. Cosmetic
// only (styled output); the plain path always shows the full path.
func prettyPath(p string) string {
	if h, err := os.UserHomeDir(); err == nil && h != "" && strings.HasPrefix(p, h) {
		return "~" + p[len(h):]
	}
	return p
}

// padr right-pads s to width w, measured in terminal columns. Callers apply
// colour after padding, so ANSI never skews alignment.
//
// Columns and not runes: a rune count is right only for text that is entirely
// single-width, and the values padded here (agent names, statuses) are not
// guaranteed to be. A CJK name is half as many runes as the columns it
// occupies, so a rune count over-pads it and the column to its right lands
// in the wrong place. runewidth is already a direct dependency.
func padr(s string, w int) string {
	if n := w - runewidth.StringWidth(s); n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
}

// styledStatus colours a `constle ps` status: running is live (green), settled
// states are muted, anything unexpected is amber.
func styledStatus(s string) string {
	initStyles()
	switch s {
	case "running":
		return stGreen.Render(s)
	case "exited", "dead", "created", "removing", "paused":
		return stMuted.Render(s)
	default:
		return stAmber.Render(s)
	}
}

// ------------------------------------------------------------
// Spinner (TTY only). Non-styled degrades to the exact printStep/printOK
// two-line behaviour, so piped output is unchanged.
// ------------------------------------------------------------

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type spinner struct {
	mu     sync.Mutex // guards msg (written by set(), read by the run goroutine)
	msg    string
	active bool
	stop   chan struct{}
	done   chan struct{}
}

func startSpinner(format string, args ...any) *spinner {
	msg := termsafe.Line(fmt.Sprintf(format, args...))
	if !styled {
		printf("  → %s\n", msg)
		return &spinner{msg: msg}
	}
	initStyles()
	s := &spinner{msg: msg, active: true, stop: make(chan struct{}), done: make(chan struct{})}
	go s.run()
	return s
}

// set updates a live spinner's message in place — the mechanism that lets a
// sequence of setup steps overwrite a single line (collapse) rather than each
// leaving a permanent row. On the non-styled path there is no live line, so it
// falls back to a fresh plain step line (identical to a new startSpinner).
func (s *spinner) set(format string, args ...any) {
	msg := termsafe.Line(fmt.Sprintf(format, args...))
	if !s.active {
		printf("  → %s\n", msg)
		return
	}
	s.mu.Lock()
	s.msg = msg
	s.mu.Unlock()
}

func (s *spinner) run() {
	defer close(s.done)
	t := time.NewTicker(90 * time.Millisecond)
	defer t.Stop()
	s.draw(spinFrames[0])
	i := 0
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			i = (i + 1) % len(spinFrames)
			s.draw(spinFrames[i])
		}
	}
}

func (s *spinner) draw(frame string) {
	s.mu.Lock()
	msg := s.msg
	s.mu.Unlock()
	printf("\r%s%s %s\x1b[K", indent, stAccent.Render(frame), stMuted.Render(msg))
}

// ok stops the spinner and replaces it with a success line. Non-styled: prints
// the plain "  ✓ msg" line, identical to printOK. Sets active=false so a later
// stopClear (e.g. a deferred cleanup) is a safe no-op rather than a double
// channel close.
func (s *spinner) ok(format string, args ...any) {
	msg := termsafe.Line(fmt.Sprintf(format, args...))
	if !s.active {
		printf("  ✓ %s\n", msg)
		return
	}
	close(s.stop)
	<-s.done
	s.active = false
	printf("\r%s%s %s\x1b[K\n", indent, stGreen.Render("✓"), stInk.Render(msg))
}

func (s *spinner) stopClear() {
	if !s.active {
		return
	}
	close(s.stop)
	<-s.done
	s.active = false
	printf("\r\x1b[K")
}
