package mcpgate

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
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
// forever or returns garbage), and neither is /dev/null — it is a character
// device like a tty, but delivers only instant EOF, the standard stdin of
// daemonized runs.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if nullInfo, err := os.Stat(os.DevNull); err == nil && os.SameFile(info, nullInfo) {
		return false
	}
	return true
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

	args := string(req.Arguments)
	if len(args) > 500 {
		args = args[:500] + "…"
	}

	fmt.Fprintf(a.Out, "\n⏸  human gate: agent %q wants to call MCP tool %q on server %q\n",
		req.AgentName, req.Tool, req.ServerID)
	if args != "" {
		fmt.Fprintf(a.Out, "   arguments: %s\n", args)
	}

	if !a.Interactive {
		fmt.Fprintf(a.Out, "   stdin is not a terminal — cannot prompt for approval\n")
		fmt.Fprintf(a.Out, "   applying on_timeout=%q in %ds\n", req.OnTimeout, req.TimeoutSeconds)
		<-ctx.Done()
		return DecisionNone
	}

	a.readOnce.Do(a.startReader)

	// Discard lines typed before this prompt existed — a stale keystroke
	// must never approve a gate it was not aimed at. Stops on a closed
	// channel (EOF) too: a closed channel always receives, ok=false.
drain:
	for {
		select {
		case _, ok := <-a.lineCh:
			if !ok {
				break drain
			}
		default:
			break drain
		}
	}

	fmt.Fprintf(a.Out, "   approve? [a]pprove / [d]eny (timeout %ds → %s): ",
		req.TimeoutSeconds, req.OnTimeout)

	for {
		select {
		case line, ok := <-a.lineCh:
			if !ok {
				// Input closed (EOF): no human can answer; wait for timeout.
				<-ctx.Done()
				return DecisionNone
			}
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "a", "approve", "y", "yes":
				return DecisionApproved
			case "d", "deny", "n", "no":
				return DecisionDenied
			default:
				fmt.Fprintf(a.Out, "   please answer [a]pprove or [d]eny: ")
			}
		case <-ctx.Done():
			fmt.Fprintf(a.Out, "\n   gate timed out waiting for input\n")
			return DecisionNone
		}
	}
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
