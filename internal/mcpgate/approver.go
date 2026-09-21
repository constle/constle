package mcpgate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/mattn/go-isatty"

	"github.com/constle/constle/internal/termsafe"
)

// The three budgets below bound what one terminal approval can cover. Above
// any of them the prompt refuses outright rather than showing a prefix,
// because an operator cannot consent to bytes they were not shown.
//
// Three and not one, because each bounds a different thing an agent controls
// independently, and any one alone is bypassable:
//
//   - maxDisplayedArgumentBytes bounds the call itself. It is the cheap
//     pre-check that keeps a 10 MB body (the gate accepts up to maxBodyBytes)
//     from being rendered at all.
//   - maxDisplayedLines bounds what the operator has to read. Raw size does
//     not: a 4 KiB flat array of one-character elements is 2,049 lines, since
//     json.Indent puts every element on its own.
//   - maxRenderedBytes bounds the volume written to the terminal. Line count
//     does not: json.Indent emits 3+2*depth spaces per line, so rendered size
//     grows with the SQUARE of nesting depth. 4 KiB of `[[[[…]]]]` at depth
//     2000 renders to 8.4 MB — enough to evict the header, the subject digest
//     and the first key from any terminal's scrollback while every line is,
//     technically, printed.
//
// The numbers are a judgement about what a person can actually review at a
// prompt, not a protocol limit: a webhook approver with a real UI still
// decides calls of any size. They are deliberately constants rather than
// human_gates fields — a limit whose whole job is to bound what the
// Agentfile's own tool calls can hide from the operator must not be raisable
// from the Agentfile.
const (
	maxDisplayedArgumentBytes = 4 << 10  // raw params.arguments
	maxRenderedBytes          = 16 << 10 // the text actually printed
	maxDisplayedLines         = 200      // ~a few screens, scrollable
)

// TerminalApprover collects approve/deny decisions from the operator's
// terminal. It is the interim local approval path until a cloud approval
// bridge exists.
//
// When stdin is not a terminal (run backgrounded with `&`, piped stdin,
// CI), prompting would block on a read that never resolves — so the
// approver detects this up front, prints one notice, and simply waits for
// the context deadline, letting the gate's on_timeout policy decide.
type TerminalApprover struct {
	// In is the decision input, normally os.Stdin.
	In io.Reader

	// Out receives the prompt. The CLI passes a writer that holds its
	// stdout lock, preserving the stdout serialisation invariant.
	Out io.Writer

	// Interactive reports whether In is a terminal a human can answer on.
	// Use NewTerminalApprover to detect it from the real stdin.
	Interactive bool

	// mu serialises concurrent gated calls so their prompts never interleave.
	mu sync.Mutex

	// readOnce starts the single long-lived stdin reader. One reader for the
	// approver's lifetime — a per-prompt reader would leak a goroutine
	// blocked on stdin at every timeout, and a keystroke meant for an
	// expired prompt could then be consumed as the answer to a later one.
	readOnce sync.Once
	lineCh   chan string
}

// NewTerminalApprover builds a TerminalApprover on the process's real
// stdin/stdout, detecting whether stdin is a terminal.
func NewTerminalApprover(out io.Writer) *TerminalApprover {
	return &TerminalApprover{
		In:          os.Stdin,
		Out:         out,
		Interactive: stdinIsTerminal(),
	}
}

// stdinIsTerminal reports whether os.Stdin is a terminal a human can answer
// on. Pipes and files are not (reading a prompt answer from those blocks
// forever or returns garbage), and neither is /dev/null or Windows NUL — a
// character device like a tty, but one that delivers only instant EOF, the
// standard stdin of daemonized runs.
//
// This uses mattn/go-isatty (ioctl on unix, GetConsoleMode on Windows) rather
// than a hand-rolled os.Stat + SameFile(os.DevNull) check, because SameFile is
// not correct on Windows: Stat fills the volume/file-index identity fields
// only for real files, so every character device — a live console just as much
// as NUL — carries the same all-zero identity and compares equal. That made
// this function return false on every Windows console, silently downgrading
// interactive human gates to "resolve by timeout" for all Windows users.
// cmd/constle/style.go's detectStyled() gates stdout on isatty for exactly
// this reason; stdin now matches.
func stdinIsTerminal() bool {
	fd := os.Stdin.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// Decide prompts for a decision, or — when non-interactive — announces that
// the gate will resolve by timeout and blocks until ctx expires.
func (a *TerminalApprover) Decide(ctx context.Context, req Request) Decision {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Re-check ctx after acquiring the lock: a previous prompt may have
	// consumed the whole timeout while this call queued.
	if ctx.Err() != nil {
		return DecisionNone
	}

	outf(a.Out, "\n⏸  human gate: agent %q wants to call MCP tool %q on server %q\n",
		req.AgentName, req.Tool, req.ServerID)
	if req.SubjectDigest != "" {
		outf(a.Out, "   subject: %s\n", req.SubjectDigest)
	}

	// An approval this terminal cannot show in full is an approval it must
	// not collect — but refusing to ASK is not the same as refusing to LET
	// THE OPERATOR SAY NO. Dropping the prompt entirely would hand the agent
	// a way to make a call undeniable: pad the arguments past a budget, and
	// under on_timeout=proceed the call is forwarded with no human able to
	// intervene at all, where before it could be denied in two seconds. So
	// the prompt stays live here and only the approve half is withdrawn.
	if block, why := displayableArguments(req.Arguments); why != "" {
		outf(a.Out, "   %s\n"+
			"   these arguments cannot be shown here, so this terminal will not\n"+
			"   collect an approval for them — deny now, or let on_timeout=%q\n"+
			"   decide in %ds (a human_gates.notify webhook approver, which has no\n"+
			"   display budget, can still approve a call this size)\n",
			why, req.OnTimeout, req.TimeoutSeconds)
		return a.denyOnly(ctx, req)
	} else {
		// Printed above the !a.Interactive branch on purpose: what the
		// operator is shown must not depend on whether they can answer, and a
		// backgrounded run's transcript is the only record of what its gates
		// were asked about.
		// Preformatted: renderArguments already escaped every line of this
		// block, and the newlines between them are constle's own.
		outf(a.Out, "%s", termsafe.Preformatted(block))
	}

	if !a.Interactive {
		outf(a.Out, "   stdin is not a terminal — cannot prompt for approval\n")
		outf(a.Out, "   applying on_timeout=%q in %ds\n", req.OnTimeout, req.TimeoutSeconds)
		<-ctx.Done()
		return DecisionNone
	}

	a.beginPrompt()

	outf(a.Out, "   approve? [a]pprove / [d]eny (timeout %ds → %s): ",
		req.TimeoutSeconds, req.OnTimeout)

	for {
		line, ok, expired := a.readAnswer(ctx)
		if expired {
			outf(a.Out, "\n   gate timed out waiting for input\n")
			return DecisionNone
		}
		if !ok {
			// Input closed (EOF): no human can answer; wait for timeout.
			<-ctx.Done()
			return DecisionNone
		}
		switch line {
		case "a", "approve", "y", "yes":
			return DecisionApproved
		case "d", "deny", "n", "no":
			return DecisionDenied
		default:
			outf(a.Out, "   please answer [a]pprove or [d]eny: ")
		}
	}
}

// denyOnly runs the prompt for a call whose arguments could not be displayed:
// the operator can still veto it immediately, but no answer approves it.
//
// Returning DecisionDenied only on an explicit "no" — and DecisionNone
// otherwise — is what keeps this composable. RaceApprover (race_approver.go)
// treats DecisionNone as "this source has not answered" and keeps waiting on
// the others, so a webhook approver holding the full bytes still gets its
// whole window; a blanket denial here would let this terminal's rendering
// budget veto an approver that has no rendering budget. It also keeps the
// audit trail honest: gate_denied is written with decided_by "terminal", and
// that must never name a decision no human actually made.
func (a *TerminalApprover) denyOnly(ctx context.Context, req Request) Decision {
	if !a.Interactive {
		outf(a.Out, "   stdin is not a terminal — cannot prompt\n")
		outf(a.Out, "   applying on_timeout=%q in %ds\n", req.OnTimeout, req.TimeoutSeconds)
		<-ctx.Done()
		return DecisionNone
	}

	a.beginPrompt()
	outf(a.Out, "   [d]eny? (no approval is offered; timeout %ds → %s): ",
		req.TimeoutSeconds, req.OnTimeout)

	for {
		line, ok, expired := a.readAnswer(ctx)
		if expired {
			outf(a.Out, "\n   gate timed out waiting for input\n")
			return DecisionNone
		}
		if !ok {
			<-ctx.Done()
			return DecisionNone
		}
		switch line {
		case "d", "deny", "n", "no":
			return DecisionDenied
		case "a", "approve", "y", "yes":
			outf(a.Out, "   cannot approve arguments that were never shown — [d]eny or wait: ")
		default:
			outf(a.Out, "   please answer [d]eny, or wait for the timeout: ")
		}
	}
}

// beginPrompt starts the stdin reader if needed and discards lines typed
// before this prompt existed — a stale keystroke must never answer a gate it
// was not aimed at. Stops on a closed channel (EOF) too: a closed channel
// always receives, ok=false.
func (a *TerminalApprover) beginPrompt() {
	a.readOnce.Do(a.startReader)
	for {
		select {
		case _, ok := <-a.lineCh:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

// readAnswer waits for one normalised answer. ok is false when the input
// closed (EOF); expired is true when ctx ended first.
func (a *TerminalApprover) readAnswer(ctx context.Context) (line string, ok bool, expired bool) {
	select {
	case raw, open := <-a.lineCh:
		if !open {
			return "", false, false
		}
		return strings.ToLower(strings.TrimSpace(raw)), true, false
	case <-ctx.Done():
		return "", false, true
	}
}

// displayableArguments renders raw for the prompt, or reports in why the one
// reason it cannot be shown in full. why is empty exactly when block holds
// every byte of the call.
func displayableArguments(raw json.RawMessage) (block string, why string) {
	if len(raw) == 0 {
		return "   arguments: (none)\n", ""
	}
	if len(raw) > maxDisplayedArgumentBytes {
		return "", fmt.Sprintf("arguments are %d bytes, over the %d-byte limit for one prompt",
			len(raw), maxDisplayedArgumentBytes)
	}

	text, lines := renderArguments(raw)
	switch {
	case lines > maxDisplayedLines:
		return "", fmt.Sprintf("arguments render to %d lines, over the %d-line limit for one prompt",
			lines, maxDisplayedLines)
	case len(text) > maxRenderedBytes:
		return "", fmt.Sprintf("arguments render to %d bytes of text, over the %d-byte limit for one prompt",
			len(text), maxRenderedBytes)
	}

	return fmt.Sprintf("   arguments (%d bytes, %d lines) — shown in full:\n%s\n", len(raw), lines, text), ""
}

// renderArguments turns a gated call's raw params.arguments into the exact
// text the operator is shown, and reports how many lines that is. Every byte
// of the input is represented in the output: this function never elides.
//
// Two passes, in this order, and the order is the point:
//
//  1. json.Indent re-derives ALL the structural whitespace from the parsed
//     token stream, discarding whatever the agent wrote between tokens. That
//     is what stops the agent from controlling the display's line structure
//     — no forged prompt lines, no carriage return that erases the line
//     above, no cut aligned to a closing brace that makes a partial object
//     read as a finished one. It also puts one key per line, which is what
//     makes reading the thing realistic rather than nominal.
//
//  2. termsafe.Line on each resulting line, for the hostile runes that
//     survive a parse because they are legal inside a JSON string.
//
// What reaches step 2 is narrower than what termsafe.Line defends against in
// general. encoding/json's scanner rejects a raw ESC — and every other byte
// below 0x20 — inside a string literal, so classical CSI injection cannot
// arrive by this route at all. What JSON does permit is every byte >= 0x80,
// including invalid UTF-8 and the runes that attack a reader rather than a
// terminal: U+202E RIGHT-TO-LEFT OVERRIDE reverses the displayed text, U+200B
// and U+FEFF are invisible, U+2028 is a line separator to some renderers,
// U+00A0 is an unselectable space. A body that reads as one transfer and
// executes as another needs none of them to be printable.
//
// No extra backslash-doubling is needed to keep the rendering unambiguous,
// because what is being displayed is JSON *source*: a backslash there is
// always already escaped as two backslashes, so a body that spells an escape
// sequence literally keeps its doubled backslash on screen and stays distinct
// from the single-backslash escape termsafe emits for a raw rune. The one
// collision left is between a source that writes the bidi override as a JSON
// \\u escape and one that writes it as raw UTF-8: those two bodies decode to
// the identical string at the upstream, so rendering them alike is correct,
// not lossy.
//
// Indent failing is unreachable through the gate proxy — parseJSONRPC has
// already unmarshalled the whole body, and encoding/json validates a
// json.RawMessage's contents — but Decide is exported, so the fallback
// prints the raw bytes through the same escaper rather than printing
// nothing. Showing something unparseable is recoverable; showing nothing
// while still offering an approve prompt is the bug this file is fixing.
func renderArguments(raw json.RawMessage) (text string, lines int) {
	const linePrefix = "   "

	var indented bytes.Buffer
	if err := json.Indent(&indented, raw, linePrefix, "  "); err != nil {
		// Not parseable: there is no structure to re-derive, so the whole
		// body becomes ONE line. Not splitting is the point — an unparseable
		// body is the only input whose newlines constle did not write, and
		// letting those through is what would let a caller-supplied body
		// print lines indistinguishable from the prompt's own. termsafe.Line
		// escapes them (\n is not a printable rune) along with everything
		// else.
		return linePrefix + termsafe.Line(string(raw)), 1
	}

	// json.Indent prefixes every line but the first, so the first gets one
	// here. After Indent the only newlines are the ones it wrote itself.
	var b strings.Builder
	for i, line := range strings.Split(indented.String(), "\n") {
		if i > 0 {
			b.WriteByte('\n')
		} else {
			b.WriteString(linePrefix)
		}
		b.WriteString(termsafe.Line(line))
		lines++
	}
	return b.String(), lines
}

// startReader launches the approver's single stdin reader goroutine. It
// lives until In reaches EOF; the channel is unbuffered so a line typed with
// no prompt waiting parks here until drained by the next prompt.
func (a *TerminalApprover) startReader() {
	a.lineCh = make(chan string)
	go func() {
		defer close(a.lineCh)
		scanner := bufio.NewScanner(a.In)
		for scanner.Scan() {
			a.lineCh <- scanner.Text()
		}
	}()
}
