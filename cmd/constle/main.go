package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/constle/constle/internal/a2a"
	"github.com/constle/constle/internal/audit"
	"github.com/constle/constle/internal/identity"
	"github.com/constle/constle/internal/mcpgate"
	"github.com/constle/constle/internal/sandbox"
	"github.com/constle/constle/pkg/manifest"
)

var constleVersion = "0.4.0"

// stdoutMu serialises all writes to stdout.
//
// The signal goroutine (started in cmdRun) can print at any moment, including
// after the agent exits naturally and the main goroutine has unblocked from
// Wait(). Without this lock the two goroutines race on os.Stdout, producing
// interleaved output. The lock is never contended during normal (non-signal)
// operation, so the overhead is negligible.
var stdoutMu sync.Mutex

// printf is the single path for all stdout writes in this package.
// Callers must NOT hold stdoutMu when calling printf (not reentrant).
// (Exception: warnUnenforcedHumanGates in gates.go writes via a swappable
// writer for tests, but holds stdoutMu directly to keep the same invariant.)
func printf(format string, args ...any) {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	fmt.Printf(format, args...)
}

// lockedStdout adapts stdout for the MCP gate's prompt and warnings, which
// print from gate goroutines at arbitrary times. Each Write holds stdoutMu,
// preserving the serialisation invariant documented on printf.
type lockedStdout struct{}

func (lockedStdout) Write(p []byte) (int, error) {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	return os.Stdout.Write(p)
}

// auditLog records one run-lifecycle event.
//
// Unlike the gates, cmdRun has an error path — but not a useful place to
// stop: every event written here describes something that has already
// happened (the sandbox started, the run was terminated, the agent exited),
// so abandoning the run on a failed write would discard the outcome
// reporting without un-doing anything. The loss is announced immediately
// instead, and cmdRun consults logger.Err() before it reports a run as
// cleanly finished.
func auditLog(logger *audit.Logger, runID, agentName string, event audit.EventType, details map[string]any) {
	if err := logger.Log(runID, agentName, event, details); err != nil {
		audit.WarnWriteFailure(event, err)
	}
}

// killAgent stops the agent sandbox for one of the run-terminating reasons
// (human-gate abort, spending cap, operator signal, duration limit).
//
// A kill that fails is precisely the case the operator must not be left
// guessing about: constle has just announced that it is stopping the agent,
// and if that did not take effect the agent is still running with whatever
// access the run granted it. Callers are goroutines with no error path, so
// the failure goes to stderr.
func killAgent(backend sandbox.SandboxBackend, runCtx *sandbox.RunContext, reason string) {
	if err := backend.Kill(runCtx); err != nil {
		fmt.Fprintf(os.Stderr,
			"  warning: %s: could not stop the agent: %v\n"+
				"           the sandbox may still be running — check `constle ps`\n", reason, err)
	}
}

func main() {
	args, noAnimation := parseGlobalArgs(os.Args[1:])
	if len(args) == 0 {
		if shouldPlayBootAnimation(args, noAnimation) {
			switch playBootAnimation(constleVersion) {
			case bootAnimationComplete:
				printPostIntroHelp()
			case bootAnimationInterrupted:
				os.Exit(130)
			case bootAnimationTerminated:
				os.Exit(143)
			default:
				// The intro is decorative: a resize or write failure must never
				// prevent the CLI's real help from being available.
				printHelp()
			}
			return
		}
		printHelp()
		return
	}

	switch args[0] {

	case "init":
		if err := cmdInit(); err != nil {
			die("%v", err)
		}

	case "run":
		opts, err := parseRunArgs(args[1:])
		if err != nil {
			die("%v", err)
		}
		if err := cmdRun(opts); err != nil {
			die("%v", err)
		}

	case "validate":
		if len(args) < 2 {
			die("usage: constle validate <agentfile.yaml>")
		}
		if err := cmdValidate(args[1]); err != nil {
			die("%v", err)
		}

	case "identity":
		if err := cmdIdentity(args[1:]); err != nil {
			die("%v", err)
		}

	case "webhook-keygen":
		name, err := parseWebhookKeygenArgs(args[1:])
		if err != nil {
			die("%v", err)
		}
		if err := cmdWebhookKeygen(name); err != nil {
			die("%v", err)
		}

	case "audit":
		if len(args) < 2 || args[1] != "verify" {
			die("usage: constle audit verify [--did=<did:key:…>] <logfile>")
		}
		logPath, expectedDID, err := parseAuditVerifyArgs(args[2:])
		if err != nil {
			die("%v", err)
		}
		if err := cmdAuditVerify(logPath, expectedDID); err != nil {
			die("%v", err)
		}

	case "ps":
		if err := runPS(); err != nil {
			die("%v", err)
		}

	case "stop":
		if len(args) < 2 {
			die("usage: constle stop <run_id>")
		}
		if err := cmdStop(args[1]); err != nil {
			die("%v", err)
		}

	case "version":
		fmt.Printf("constle v%s\n", constleVersion)

	case "help", "--help", "-h":
		printHelp()

	default:
		die("unknown command %q\nrun 'constle help' for usage", args[0])
	}
}

// parseGlobalArgs consumes only flags that apply before command dispatch.
// Keeping the flag global prevents it from leaking into subcommand parsers,
// while preserving every existing subcommand argument contract.
func parseGlobalArgs(args []string) (remaining []string, noAnimation bool) {
	for len(args) > 0 && args[0] == "--no-animation" {
		args = args[1:]
		noAnimation = true
	}
	return args, noAnimation
}

// runUsage is the one-line usage string for `constle run`, repeated by every
// argument error so the flags are always discoverable at the point of failure.
const runUsage = "usage: constle run [--backend=docker|firecracker] " +
	"[--accept-isolation=<level>] <agentfile.yaml>"

// runOptions is the parsed form of `constle run` arguments.
type runOptions struct {
	// agentfile is the path to the Agentfile to run.
	agentfile string

	// backendOverride forces a sandbox engine (--backend). It selects an
	// engine only — it never relaxes the manifest's isolation contract.
	backendOverride string

	// acceptIsolation is the operator's explicit acknowledgement
	// (--accept-isolation=<level>) that this run may proceed with a weaker
	// boundary than the Agentfile declares. Empty means no downgrade is
	// permitted and an unsatisfiable contract aborts the run.
	acceptIsolation manifest.IsolationLevel
}

// parseRunArgs extracts the Agentfile path and the optional flags from
// `constle run` arguments.
//
// --accept-isolation is validated here rather than at selection time: a typo
// in the level must never be read as "some downgrade was requested", because
// that is the one input that can weaken a declared boundary.
func parseRunArgs(args []string) (runOptions, error) {
	var opts runOptions

	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--backend="):
			opts.backendOverride = strings.TrimPrefix(arg, "--backend=")
		case strings.HasPrefix(arg, "--accept-isolation="):
			level, err := manifest.ParseIsolationLevel(strings.TrimPrefix(arg, "--accept-isolation="))
			if err != nil {
				return runOptions{}, fmt.Errorf("--accept-isolation: %w", err)
			}
			opts.acceptIsolation = level
		case strings.HasPrefix(arg, "-"):
			return runOptions{}, fmt.Errorf("unknown flag %q\n%s", arg, runUsage)
		case opts.agentfile == "":
			opts.agentfile = arg
		default:
			return runOptions{}, fmt.Errorf("unexpected argument %q", arg)
		}
	}
	if opts.agentfile == "" {
		return runOptions{}, fmt.Errorf("%s", runUsage)
	}
	return opts, nil
}

// achievedLabel renders the boundary a run actually got, naming the requested
// level alongside it when the two differ. A bare "network" on a run whose
// manifest asked for "kernel" would be true and still misleading — the point
// of the contract is that the gap stays visible wherever the level is shown.
func achievedLabel(sel *sandbox.Selection) string {
	if sel.Downgraded {
		return fmt.Sprintf("%s (requested %s, downgrade accepted)", sel.Achieved, sel.Requested)
	}
	return string(sel.Achieved)
}

// isolationOrigin says where the manifest's isolation level came from, for
// the one-word qualifier the validate output carries beside it.
//
// It used to be hardcoded to "inferred from capabilities", which was wrong
// whenever the Agentfile declared a level — and actively misleading for a
// malformed one, since it credited the runtime with a choice the operator had
// actually written by hand. Validate now rejects a malformed level outright,
// but the label stays honest either way.
func isolationOrigin(m *manifest.AgentManifest) string {
	if m.Sandbox.IsolationInferred {
		return "inferred from capabilities"
	}
	return "declared in the Agentfile"
}

// runStartedDetails builds the details map for the run_started audit event.
//
// The entry's isolation_level records what the Agentfile REQUIRED;
// isolation_achieved records what the sandbox actually delivers. They are
// separate fields because they can legitimately differ — but only via an
// explicit operator downgrade, which the entry then names outright. A reader
// of the log can therefore never mistake a requested boundary for an
// enforced one.
func runStartedDetails(m *manifest.AgentManifest, sel *sandbox.Selection) map[string]any {
	details := map[string]any{
		"backend":            string(sel.Type),
		"image":              m.Sandbox.Image,
		"isolation_achieved": string(sel.Achieved),
	}
	if sel.Downgraded {
		details["isolation_downgrade_accepted"] = true
	}
	return details
}

func cmdRun(opts runOptions) error {
	agentfilePath := opts.agentfile
	printHeader()

	// Parsing is transient in styled mode: a self-clearing spinner that leaves
	// no permanent row before the summary (density). Plain mode keeps its exact
	// two-line step/ok output for byte-identical piped/captured output.
	var pSpin *spinner
	if styled {
		pSpin = startSpinner("parsing %s", prettyPath(agentfilePath))
	} else {
		printStep("parsing %s", agentfilePath)
	}

	m, err := manifest.ParseFile(agentfilePath)
	if err != nil {
		if pSpin != nil {
			pSpin.stopClear()
		}
		return fmt.Errorf("cannot parse Agentfile: %w", err)
	}
	if err := m.Validate(); err != nil {
		if pSpin != nil {
			pSpin.stopClear()
		}
		return fmt.Errorf("invalid Agentfile: %w", err)
	}
	if pSpin != nil {
		pSpin.stopClear()
	} else {
		printOK("Agentfile valid")
	}

	if styled {
		renderRunSummary(m)
	} else {
		printRunSummaryPlain(m)
	}

	warnUnenforcedHumanGates(m)
	warnUnenforcedSpending(m)

	// Setup phase — collapses to a single settled line in styled mode; in plain
	// mode each step keeps its own → / ✓ line. fail() (deferred) clears the
	// collapsing line on any early error return; it is a no-op once settled.
	setup := newSetup()
	defer setup.fail()

	setup.step("detecting backend")

	sel, err := sandbox.DetectBestBackend(m.Sandbox.Isolation, opts.backendOverride, opts.acceptIsolation)
	if err != nil {
		return err
	}
	backend, backendType := sel.Backend, sel.Type
	// The backend name alone does not say what boundary the run got, so the
	// achieved isolation rides with it.
	setup.ok("backend: %s  ∙  isolation %s", backendType, achievedLabel(sel))
	setup.gap()

	logLoc, err := audit.DefaultLogLocation(m.Identity.Name)
	if err != nil {
		return err
	}
	logPath := logLoc.String()

	// Fail closed on identity: when the Agentfile declares identity.did,
	// every audit entry must be signed with the matching local key — running
	// unsigned while the manifest promises a signed log would make the
	// declared protection a lie (same principle as warnUnenforcedHumanGates).
	// The loaded identity also signs outbound A2A calls, so it is kept for
	// the A2A gate below.
	var runIdentity *identity.Identity
	var logger *audit.Logger
	// identityNote holds the styled identity line, printed once after the setup
	// phase settles so it does not interrupt the collapsing line. It is a
	// security fact (signed, hash-chained audit log), so it stays visible —
	// just de-emphasized to a single dim line rather than a two-line block.
	var identityNote string
	if m.Identity.DID != "" {
		runIdentity, err = loadRunIdentity(m)
		if err != nil {
			return err
		}
		logger, err = audit.NewSigned(logLoc, runIdentity)
		if err != nil {
			return fmt.Errorf("cannot open signed audit log: %w", err)
		}
		if styled {
			identityNote = fmt.Sprintf("identity %s  ∙  audit log signed (Ed25519, hash-chained)", runIdentity.DID())
		} else {
			printOK("identity: %s", runIdentity.DID())
			printf("     audit log entries are Ed25519-signed and hash-chained\n\n")
		}
	} else {
		var err error
		logger, err = audit.New(logLoc)
		if err != nil {
			return fmt.Errorf("cannot open audit log: %w", err)
		}
	}
	defer func() {
		// A close failure can be the first sight of an I/O problem that also
		// cost the run entries (a full disk surfaces at close as often as at
		// write), so it is reported rather than dropped.
		if err := logger.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not close the audit log %s: %v\n", logPath, err)
		}
	}()

	if m.Identity.DID != "" && !logger.Signed() {
		// Unreachable by construction; guards against future refactors ever
		// letting a declared identity run with an unsigned log.
		return fmt.Errorf("internal error: identity.did is declared but the audit logger is not signing — refusing to run")
	}

	// Spending enforcement: cost is metered at the MCP gate for servers
	// that declare pricing. When a daily cap exists this also opens the
	// durable per-DID ledger and refuses to start a run whose budget is
	// already exhausted — fail closed, before any sandbox resources exist.
	tracker, err := buildSpendingTracker(m, logger)
	if err != nil {
		return err
	}

	// Human-gate enforcement: every declared MCP server is reachable from
	// the sandbox only through this gate proxy, which pauses gated tool
	// calls for approval. The gate lives in this process — it owns the
	// terminal the approve/deny prompt needs.
	var gate *mcpgate.Gate
	if len(m.MCP.Servers) > 0 {
		var approver mcpgate.Approver = mcpgate.NewTerminalApprover(lockedStdout{})

		var notifier mcpgate.Notifier
		wn := mcpgate.NewWebhookNotifier(m.HumanGates, lockedStdout{})
		if wn != nil {
			notifier = wn
		}

		// A declared approver_pubkey means an external decision endpoint can
		// also answer a gate — it runs concurrently with the terminal
		// prompt, and whichever produces a decision first wins (see
		// mcpgate.RaceApprover). It is reached at the same URL the webhook
		// notifier already posts trigger notifications to.
		switch {
		case wn != nil && m.HumanGates.ApproverPubkey != "":
			approver = mcpgate.RaceApprover{Approvers: []mcpgate.Approver{
				approver,
				&mcpgate.WebhookApprover{
					URL:            wn.URLs[0],
					ApproverPubkey: m.HumanGates.ApproverPubkey,
					Out:            lockedStdout{},
				},
			}}
		case wn == nil && m.HumanGates.ApproverPubkey != "":
			// Declared but unusable: approver_pubkey names a verifier with
			// nothing to verify, because no notify webhook URL resolved.
			// Same principle as warnUnenforcedHumanGates — a declared
			// protection must never look real when it isn't.
			printf("⚠️  warning: human_gates.approver_pubkey is set but no notify " +
				"webhook URL resolved — gated calls will only be decided at this terminal\n")
		}

		gate, err = mcpgate.New(m, approver, notifier, logger, tracker)
		if err != nil {
			return fmt.Errorf("cannot build MCP gate: %w", err)
		}
		// Close only shuts the listener down as the process exits; there is
		// no state to lose and nothing an operator could do about a listener
		// that would not close, so its error is deliberately dropped.
		defer func() { _ = gate.Close() }()

		if setter, ok := backend.(sandbox.MCPGateSetter); ok {
			setter.SetMCPGate(gate)
		} else {
			// Fail closed: never run declared MCP servers without the gate.
			return fmt.Errorf("backend %s does not support the MCP gate proxy", backendType)
		}
	}

	// A2A: every outbound call is signed (and every peer response verified)
	// by this host process with the agent's identity — the private key never
	// enters the sandbox, and peers' real endpoints never enter it either.
	var a2aGate *a2a.Gate
	if len(m.A2A.Peers) > 0 {
		// Validate() guarantees identity.did is declared whenever a2a.peers
		// exist, and the fail-closed identity block above already loaded it.
		if runIdentity == nil {
			return fmt.Errorf("internal error: a2a.peers are declared but no identity was loaded — refusing to run unsigned A2A")
		}
		a2aGate, err = a2a.New(m, runIdentity, logger)
		if err != nil {
			return fmt.Errorf("cannot build A2A gate: %w", err)
		}
		// Same as the MCP gate: process-exit listener teardown, nothing
		// actionable in a failure.
		defer func() { _ = a2aGate.Close() }()

		if setter, ok := backend.(sandbox.A2AGateSetter); ok {
			setter.SetA2AGate(a2aGate)
		} else {
			// Fail closed: never run declared A2A peers without the signing gate.
			return fmt.Errorf("backend %s does not support the A2A gate", backendType)
		}
	}

	// DockerBackend.Start() silently removes any abandoned constle containers
	// (exited/dead state) before allocating new resources. This is the same
	// collapsing line as the setup steps above (styled) — it settles below.
	setup.step("starting sandbox...")

	startTime := time.Now()

	runCtx, err := backend.Start(m)
	if err != nil {
		// setup.fail() (deferred) clears the collapsing line.
		auditLog(logger, "", m.Identity.Name, audit.EventRunFailed,
			map[string]any{"error": err.Error()})
		return fmt.Errorf("cannot start sandbox: %w", err)
	}

	// runSucceeded is set true only on the clean exit-0 path (the final success
	// return, below). The deferred teardown closure reads it to decide how loud
	// to be: on SUCCESS the teardown collapses (styled self-clearing spinners)
	// so the outcome pill stays the last word; on any FAILURE it renders the
	// permanent ✓ lines instead — full visibility is more useful for debugging a
	// failed run than the compact treatment.
	var runSucceeded bool

	// Squid logs must be read before Stop() removes the proxy container
	// (Docker) or the run directory (Firecracker). Teardown is secondary on a
	// clean run, but diagnostic on a failed one; plain mode always keeps its
	// permanent ✓ lines, byte-for-byte unchanged. A teardown that itself errors
	// always surfaces on stderr, regardless of outcome or styling.
	defer func() {
		nlSpin := startSpinner("reading network audit logs...")
		var flushErr error
		if runCtx.SquidAccessLog != "" {
			flushErr = audit.FlushSquidLogFile(runCtx.RunID, m.Identity.Name, runCtx.SquidAccessLog, logger)
		} else {
			flushErr = audit.FlushSquidLogs(runCtx.RunID, m.Identity.Name, runCtx.ProxyContainerID, logger)
		}
		if flushErr != nil {
			// Covers both halves of the flush: reading Squid's access log,
			// and recording what it contained as audit events. Either way
			// the run's network activity is not fully in the audit log.
			nlSpin.stopClear()
			fmt.Fprintf(os.Stderr, "  warning: network events were not fully logged: %v\n", flushErr)
		} else if styled && runSucceeded {
			nlSpin.stopClear()
		} else {
			nlSpin.ok("network events logged")
		}

		if !styled || !runSucceeded {
			printf("\n")
		}
		cuSpin := startSpinner("cleaning up sandbox...")
		if err := backend.Stop(runCtx); err != nil {
			cuSpin.stopClear()
			fmt.Fprintf(os.Stderr, "  warning: cleanup error: %v\n", err)
		} else if styled && runSucceeded {
			cuSpin.stopClear()
		} else {
			cuSpin.ok("sandbox removed")
		}
	}()

	if err := logger.LogWithIsolation(
		runCtx.RunID, m.Identity.Name,
		audit.EventRunStarted,
		string(m.Sandbox.Isolation),
		runStartedDetails(m, sel),
	); err != nil {
		audit.WarnWriteFailure(audit.EventRunStarted, err)
	}

	// Settle the collapsing setup line to one permanent row (styled), or print
	// the exact "sandbox started (run_id: …)" ✓ line (plain).
	// Full run_id on the persistent settled line — this is the live line during
	// execution, exactly when a second terminal would need it for `constle stop`.
	// The post-run footer keeps a short handle (correlation only).
	//
	// The achieved isolation rides on this line because in styled mode it is
	// the ONLY permanent setup row: setup.ok folds into the collapsing line
	// and is overwritten, so the boundary the run actually got would otherwise
	// survive nowhere on screen. The plain path already prints it as its own
	// permanent ✓ row, so its bytes stay untouched here.
	setup.settle(
		fmt.Sprintf("sandbox ready  ∙  %s  ∙  isolation %s  ∙  run %s",
			backendType, achievedLabel(sel), runCtx.RunID),
		"sandbox started (run_id: %s)", runCtx.RunID)

	// The signed-identity note (styled) rides just under the settled setup line
	// as one dim row — security fact kept, de-emphasized.
	if identityNote != "" {
		printf("%s%s\n", indent, stVer.Render(identityNote))
	}

	// The public A2A listener starts only after the sandbox is up: the gate
	// already carries the run id (set at Bind, mid-Start), so every inbound
	// event is attributed, and a2aGate.Close (deferred above) tears the
	// listener down with the run. Verification and peer authorization happen
	// in this process — an unverified call never has a path into the sandbox.
	if a2aGate != nil && m.A2A.Listen != "" {
		if err := a2aGate.StartListener(m.A2A.Listen); err != nil {
			return fmt.Errorf("cannot start A2A listener: %w", err)
		}
		printOK("a2a listener: %s (verified peers only)", m.A2A.Listen)
	}

	// gateAborted is closed by the MCP gate when a gated tool call times out
	// under on_timeout: abort. Checked after Wait() like limitReached, so the
	// termination is attributed to the gate.
	gateAborted := make(chan struct{})

	if gate != nil {
		var abortOnce sync.Once
		gate.SetAbortRun(func() {
			abortOnce.Do(func() {
				printf("\nconstle: human gate timed out (on_timeout: abort) — stopping agent...\n")
				close(gateAborted)
				killAgent(backend, runCtx, "human gate timeout")
			})
		})
	}

	// spendExceeded is closed by the MCP gate when metered spend crosses a
	// spending limit (or a priced response cannot be metered — fail closed).
	// The kill goes through the same backend.Kill path as
	// max_duration_seconds; no parallel kill mechanism exists. The gate has
	// also tripped itself by this point, so the agent cannot complete
	// another MCP call even before the kill lands.
	spendExceeded := make(chan struct{})

	if gate != nil && tracker != nil {
		var spendOnce sync.Once
		gate.SetSpendKill(func() {
			spendOnce.Do(func() {
				printf("\nconstle: spending limit reached (%s) — stopping agent...\n", tracker.Tripped())
				close(spendExceeded)
				killAgent(backend, runCtx, "spending limit reached")
			})
		})
	}

	// The goroutine below is the only place in this process that writes to
	// stdout from a non-main goroutine. It uses printf (which holds stdoutMu)
	// for the same reason the main path does: the signal can arrive after the
	// agent exits naturally, putting the goroutine's print concurrent with the
	// main goroutine's post-Wait output and deferred cleanup prints.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	userStopped := make(chan struct{})

	go func() {
		sig := <-sigCh
		printf("\nconstle: received %s — stopping agent...\n", sig)
		close(userStopped)
		killAgent(backend, runCtx, fmt.Sprintf("received %s", sig))
	}()

	// limitReached is closed by the timer goroutine when MaxDurationSeconds
	// elapses. It is checked (non-blocking) after Wait() returns, before the
	// userStopped check, so limit termination is attributed correctly even if
	// the user also pressed Ctrl+C.
	//
	// The timer goroutine selects on userStopped so it exits cleanly if the
	// user stops the agent first — preventing a double docker-stop.
	limitReached := make(chan struct{})

	if m.Limits.MaxDurationSeconds > 0 {
		go func() {
			select {
			case <-time.After(time.Duration(m.Limits.MaxDurationSeconds) * time.Second):
				close(limitReached)
				killAgent(backend, runCtx, "duration limit exceeded")
			case <-userStopped:
				// User stopped first; let the signal goroutine handle cleanup.
			}
		}()
	}

	// Non-TTY draws the top border before Wait (streaming frame); the styled
	// path renders one solid panel after logs are collected. Byte output on
	// the non-TTY path is unchanged.
	if !styled {
		printf("\n  ┌─ agent output ──────────────────────────\n")
	}

	exitCode, waitErr := backend.Wait(runCtx)

	var agentLines []string
	if logs, logsErr := backend.Logs(runCtx); logsErr == nil && len(logs) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(logs)), "\n") {
			if line != "" {
				if styled {
					agentLines = append(agentLines, line)
				} else {
					printf("  │ %s\n", line)
				}
			}
		}
	}

	if styled {
		printf("\n")
		renderAgentOutput("agent output", agentLines)
		printf("\n")
	} else {
		printf("  └─────────────────────────────────────────\n\n")
	}

	duration := time.Since(startTime).Round(time.Millisecond)

	select {
	case <-limitReached:
		auditLog(logger, runCtx.RunID, m.Identity.Name, audit.EventTerminatedByLimit,
			map[string]any{
				"limit_seconds": m.Limits.MaxDurationSeconds,
				"duration":      duration.String(),
			})
		finalStatus(stKindFail,
			fmt.Sprintf("⚑ agent terminated: duration limit (%ds) exceeded    duration=%s", m.Limits.MaxDurationSeconds, duration),
			"terminated",
			fmt.Sprintf("duration limit %ds exceeded", m.Limits.MaxDurationSeconds),
			logPath, runCtx.RunID, duration)
		return fmt.Errorf("agent terminated: duration limit exceeded")
	default:
	}

	select {
	case <-spendExceeded:
		details := map[string]any{
			"limit":         string(tracker.Tripped()),
			"run_total_usd": tracker.RunTotal().USD(),
			"duration":      duration.String(),
		}
		if m.Spending.MaxPerRunUSD != "" {
			details["max_per_run_usd"] = m.Spending.MaxPerRunUSD
		}
		if m.Spending.MaxPerDayUSD != "" {
			details["max_per_day_usd"] = m.Spending.MaxPerDayUSD
		}
		auditLog(logger, runCtx.RunID, m.Identity.Name, audit.EventTerminatedByLimit, details)
		finalStatus(stKindFail,
			fmt.Sprintf("⚑ agent terminated: spending limit (%s) exceeded    run_spend=$%s    duration=%s", tracker.Tripped(), tracker.RunTotal().USD(), duration),
			"terminated",
			fmt.Sprintf("spending cap  ∙  $%s", tracker.RunTotal().USD()),
			logPath, runCtx.RunID, duration)
		return fmt.Errorf("agent terminated: spending limit exceeded")
	default:
	}

	select {
	case <-gateAborted:
		// The gate itself already logged the gate_timeout event; this entry
		// records the run-level consequence.
		auditLog(logger, runCtx.RunID, m.Identity.Name, audit.EventRunFailed,
			map[string]any{
				"reason":   "human_gate_timeout_abort",
				"duration": duration.String(),
			})
		finalStatus(stKindFail,
			fmt.Sprintf("⚑ agent terminated: human gate timed out without approval (on_timeout: abort)    duration=%s", duration),
			"terminated",
			"human gate timeout",
			logPath, runCtx.RunID, duration)
		return fmt.Errorf("agent terminated: human gate timed out without approval")
	default:
	}

	select {
	case <-userStopped:
		auditLog(logger, runCtx.RunID, m.Identity.Name, audit.EventRunFailed,
			map[string]any{
				"reason":   "stopped_by_user",
				"duration": duration.String(),
			})
		finalStatus(stKindStop,
			fmt.Sprintf("⚑ agent stopped by user    duration=%s", duration),
			"stopped",
			"by user",
			logPath, runCtx.RunID, duration)
		return nil
	default:
	}

	if waitErr != nil || exitCode != 0 {
		auditLog(logger, runCtx.RunID, m.Identity.Name, audit.EventRunFailed,
			map[string]any{
				"exit_code": exitCode,
				"duration":  duration.String(),
			})
		finalStatus(stKindFail,
			fmt.Sprintf("✗ run failed    exit=%d    duration=%s", exitCode, duration),
			"failed",
			fmt.Sprintf("exit %d", exitCode),
			logPath, runCtx.RunID, duration)
		return fmt.Errorf("agent exited with code %d", exitCode)
	}

	auditLog(logger, runCtx.RunID, m.Identity.Name, audit.EventRunFinished,
		map[string]any{
			"exit_code": 0,
			"duration":  duration.String(),
		})

	// The agent exited 0 — but a clean run also means a complete record of
	// it. An entry that failed to write is simply gone, and no reader can
	// recover it: `constle audit verify` proves that the lines PRESENT are
	// signed and their chain unbroken, which is exactly why it cannot notice
	// one that was never written. Printing the success pill here would put
	// constle's own word behind a log it knows is holed, so the run reports
	// the gap instead. Every other outcome below already returns an error,
	// and each dropped entry was announced on stderr as it happened.
	if auditErr := logger.Err(); auditErr != nil {
		finalStatus(stKindFail,
			fmt.Sprintf("⚑ agent exited 0 but the audit log is incomplete    duration=%s", duration),
			"incomplete",
			"audit log incomplete",
			logPath, runCtx.RunID, duration)
		return fmt.Errorf("agent exited 0 but this run's audit log is incomplete: %w", auditErr)
	}

	finalStatus(stKindOK,
		fmt.Sprintf("✓ run finished    exit=0    duration=%s", duration),
		"done",
		"exit 0",
		logPath, runCtx.RunID, duration)

	// Clean exit only: lets the deferred teardown collapse/silence on success
	// while every failure path (which returns above) keeps it visible.
	runSucceeded = true
	return nil
}

// finalStatus prints the run outcome. Styled: the one bold moment — a solid
// filled pill (high-contrast so it stays visible on any dark theme) with the
// outcome fact beside it, over a dim dot-separated footer of secondary meta
// (audit-log path ∙ run id ∙ duration) that is deliberately de-emphasized
// below the pill (the taste reference's footer-line convention). Non-TTY: the
// exact two lines (status + audit log) constle has always printed — the `plain`
// argument is emitted verbatim, so captured output stays byte-identical.
func finalStatus(kind statusKind, plain, label, meta, auditPath, runID string, dur time.Duration) {
	if !styled {
		printf("%s\n", plain)
		printf("  audit log: %s\n\n", auditPath)
		return
	}
	initStyles()
	line := indent + pill(strings.ToUpper(label), kind)
	if meta != "" {
		line += "  " + stMuted.Render(meta)
	}
	printf("%s\n", line)

	foot := []string{"audit " + prettyPath(auditPath)}
	if runID != "" {
		foot = append(foot, "run "+shortID(runID))
	}
	if dur > 0 {
		foot = append(foot, dur.Round(100*time.Millisecond).String())
	}
	printf("%s%s\n\n", indent, stVer.Render(strings.Join(foot, "  ∙  ")))
}

// summaryCaps builds the spending-cap string and its enforcement scope,
// shared by the plain and styled run-summary renderers.
func summaryCaps(m *manifest.AgentManifest) (capsStr, scope string) {
	var caps []string
	if m.Spending.MaxPerRunUSD != "" {
		caps = append(caps, "run≤$"+m.Spending.MaxPerRunUSD)
	}
	if m.Spending.MaxPerDayUSD != "" {
		caps = append(caps, "day≤$"+m.Spending.MaxPerDayUSD)
	}
	scope = "NOT ENFORCED — no priced MCP servers"
	if priced := m.PricedMCPServers(); len(priced) > 0 {
		scope = "metered at the MCP gate: " + strings.Join(priced, ", ")
	}
	return strings.Join(caps, ", "), scope
}

func mcpIDs(m *manifest.AgentManifest) []string {
	ids := make([]string, len(m.MCP.Servers))
	for i, srv := range m.MCP.Servers {
		ids[i] = srv.ID
	}
	return ids
}

func a2aNames(m *manifest.AgentManifest) []string {
	names := make([]string, len(m.A2A.Peers))
	for i, p := range m.A2A.Peers {
		names[i] = p.Name
	}
	return names
}

// printRunSummaryPlain is the non-TTY run-summary block. It reproduces the
// exact bytes constle has always emitted — do not restyle this path.
//
// The one deliberate exception is the "(requested)" qualifier on the isolation
// row: this block is printed before backend selection, so the level it shows
// is what the Agentfile asked for, which is not necessarily what the run gets.
// Leaving it unqualified let a bare "isolation: kernel" read as an achieved
// boundary. The achieved level is reported separately once it is known.
func printRunSummaryPlain(m *manifest.AgentManifest) {
	printf("     agent:     %s v%s\n", m.Identity.Name, m.Identity.Version)
	printf("     isolation: %s (requested)\n", m.Sandbox.Isolation)
	printf("     memory:    %dMB\n", m.Sandbox.MemoryMB)
	if len(m.Sandbox.Network.AllowedHosts) > 0 {
		printf("     network:   restricted → %s\n",
			strings.Join(m.Sandbox.Network.AllowedHosts, ", "))
	}
	if m.Limits.MaxDurationSeconds > 0 {
		printf("     max_duration: %ds\n", m.Limits.MaxDurationSeconds)
	}
	if m.Spending.MaxPerRunUSD != "" || m.Spending.MaxPerDayUSD != "" {
		capsStr, scope := summaryCaps(m)
		printf("     spending:  %s (%s)\n", capsStr, scope)
	}
	if len(m.MCP.Servers) > 0 {
		printf("     mcp:       %s (via gate proxy)\n", strings.Join(mcpIDs(m), ", "))
	}
	if len(m.A2A.Peers) > 0 {
		printf("     a2a:       %s (signed via host gate)\n", strings.Join(a2aNames(m), ", "))
	}
	printf("\n")
}

// renderRunSummary draws the styled run summary (TTY only): a focal agent
// identity line followed by aligned dim-label / bright-value rows. No box — a
// near-navy fill is invisible on a typical near-black terminal, and flagship
// CLIs stay typographic here. Long values simply extend; nothing is boxed, so
// nothing wraps to a naked continuation.
func renderRunSummary(m *manifest.AgentManifest) {
	initStyles()
	printf("\n")
	subjectLine(m.Identity.Name, m.Identity.Version)

	rows := []kv{
		{"isolation", stInk.Render(string(m.Sandbox.Isolation)) + stMuted.Render("  ∙  requested")},
		{"memory", stInk.Render(fmt.Sprintf("%d MB", m.Sandbox.MemoryMB))},
	}
	// KNOWN GAP (stated rather than implied, as elsewhere): the "restricted"
	// qualifier below is hardcoded, and it is accurate only because
	// network.egress is not enforced anywhere. The field is declared on
	// manifest.Network and defaulted to "restricted" by the parser, but it has
	// no consumer: egress is derived solely from network.allowed_hosts, which
	// becomes the Squid dstdomain allowlist (an empty list denies everything).
	// So `egress: open` and `egress: none` parse cleanly, change nothing, and
	// still render as "restricted" here — a declared policy that looks real and
	// is not, which is exactly what warnUnenforcedHumanGates and
	// warnUnverifiableIdentity exist to prevent elsewhere.
	//
	// Fixing this means deciding what egress: open should DO, not just what it
	// should print; until that decision is made, this label must not be derived
	// from the field, because deriving it would make the display honest about a
	// value the runtime still ignores.
	if len(m.Sandbox.Network.AllowedHosts) > 0 {
		rows = append(rows, kv{"network", stInk.Render(strings.Join(m.Sandbox.Network.AllowedHosts, ", ")) + stMuted.Render("  ∙  restricted")})
	}
	if m.Limits.MaxDurationSeconds > 0 {
		rows = append(rows, kv{"timeout", stInk.Render(fmt.Sprintf("%ds", m.Limits.MaxDurationSeconds))})
	}
	if m.Spending.MaxPerRunUSD != "" || m.Spending.MaxPerDayUSD != "" {
		capsStr, scope := summaryCaps(m)
		val := stInk.Render(capsStr)
		if strings.HasPrefix(scope, "NOT ENFORCED") {
			val += stAmber.Render("  ∙  not enforced")
		} else {
			val += stMuted.Render("  ∙  metered")
		}
		rows = append(rows, kv{"spending", val})
	}
	if len(m.MCP.Servers) > 0 {
		rows = append(rows, kv{"mcp", stInk.Render(strings.Join(mcpIDs(m), ", ")) + stMuted.Render("  ∙  via gate")})
	}
	if len(m.A2A.Peers) > 0 {
		rows = append(rows, kv{"a2a", stInk.Render(strings.Join(a2aNames(m), ", ")) + stMuted.Render("  ∙  signed")})
	}
	renderSummaryRows(rows)
	printf("\n")
}

func cmdValidate(agentfilePath string) error {
	m, err := manifest.ParseFile(agentfilePath)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if styled {
		renderValidateStyled(agentfilePath, m)
	} else {
		printValidatePlain(agentfilePath, m)
	}

	warnUnenforcedHumanGates(m)
	warnUnenforcedSpending(m)
	warnUnverifiableIdentity(m)
	return nil
}

// printValidatePlain is the non-TTY validate output — exact bytes, unchanged.
func printValidatePlain(agentfilePath string, m *manifest.AgentManifest) {
	printf("✓ %s is valid\n\n", agentfilePath)
	printf("  name:        %s\n", m.Identity.Name)
	printf("  version:     %s\n", m.Identity.Version)
	if m.Identity.DID != "" {
		printf("  did:         %s\n", m.Identity.DID)
	}
	printf("  isolation:   %s (%s)\n", m.Sandbox.Isolation, isolationOrigin(m))
	printf("  image:       %s\n", m.Sandbox.Image)
	printf("  memory:      %dMB\n", m.Sandbox.MemoryMB)

	if len(m.Sandbox.Network.AllowedHosts) > 0 {
		printf("  allowed:     %s\n",
			strings.Join(m.Sandbox.Network.AllowedHosts, ", "))
	}

	gates := manifest.InferRequiredGates(m.Capabilities)
	if len(gates) > 0 {
		// Careful wording: capability-derived gates are spec-level advice;
		// enforcement happens on MCP tool calls whose names exactly match
		// require_approval_for entries.
		printf("  human gates: %s (approval required by spec — enforced for matching MCP tools)\n",
			strings.Join(gates, ", "))
	}

	if enforced, _ := m.EnforcedGateEntries(); len(enforced) > 0 {
		printf("  enforced:    %s (paused at the MCP gate proxy for approval)\n",
			strings.Join(enforced, ", "))
	}

	printf("\n")
}

// renderValidateStyled is the TTY validate output, matching the run aesthetic:
// a green confirmation, the agent identity, then aligned detail rows.
func renderValidateStyled(agentfilePath string, m *manifest.AgentManifest) {
	initStyles()
	printf("\n%s%s %s%s\n\n", indent, stGreen.Render("✓"),
		stInk.Render(prettyPath(agentfilePath)), stMuted.Render(" is valid"))
	subjectLine(m.Identity.Name, m.Identity.Version)

	var rows []kv
	if m.Identity.DID != "" {
		rows = append(rows, kv{"did", stInk.Render(m.Identity.DID)})
	}
	rows = append(rows,
		kv{"isolation", stInk.Render(string(m.Sandbox.Isolation)) +
			stMuted.Render("  ∙  "+isolationOrigin(m))},
		kv{"image", stInk.Render(m.Sandbox.Image)},
		kv{"memory", stInk.Render(fmt.Sprintf("%d MB", m.Sandbox.MemoryMB))},
	)
	if len(m.Sandbox.Network.AllowedHosts) > 0 {
		rows = append(rows, kv{"allowed", stInk.Render(strings.Join(m.Sandbox.Network.AllowedHosts, ", "))})
	}
	if gates := manifest.InferRequiredGates(m.Capabilities); len(gates) > 0 {
		rows = append(rows, kv{"human gates", stInk.Render(strings.Join(gates, ", ")) + stMuted.Render("  ∙  by spec")})
	}
	if enforced, _ := m.EnforcedGateEntries(); len(enforced) > 0 {
		rows = append(rows, kv{"enforced", stInk.Render(strings.Join(enforced, ", ")) + stMuted.Render("  ∙  at gate")})
	}
	renderSummaryRows(rows)
	printf("\n")
}

// ============================================================
// Helper functions
// ============================================================

func printHelp() {
	if styled {
		printStyledHelp()
		return
	}
	fmt.Printf(`constle v%s — AI agent runtime

usage:
  constle [--no-animation]      show this screen (the flag skips the animated intro)
  constle init                  create agent.yaml with sensible defaults
  constle run <agentfile>       run an agent in a sandbox
    --backend=<name>            force a backend: docker or firecracker
    --accept-isolation=<level>  run at a weaker isolation level than the
                                Agentfile declares (none|process|network)
  constle validate <agentfile>  check if an Agentfile is valid
  constle identity create <name>  create a cryptographic agent identity (did:key)
    --owner=<email>             bind the identity to an owner
  constle identity show <name>  show an agent's DID and key location
  constle webhook-keygen <name>  generate a human-gates webhook approver keypair (did:key)
  constle audit verify <logfile>  verify a signed audit log (signatures + hash chain)
    --did=<did:key:…>           pin the identity the log must be signed with
  constle ps                    list running and recent agents
  constle stop <run_id>         stop a running agent by run ID
  constle version               show version

example:
  constle init
  constle validate agent.yaml
  constle run agent.yaml
  constle ps
  constle stop a1b2c3d4e5f60708

docs: https://constle.dev
`, constleVersion)
}

func printStep(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !styled {
		printf("  → %s\n", msg)
		return
	}
	initStyles()
	printf("%s%s %s\n", indent, stMuted.Render("→"), stMuted.Render(msg))
}

func printOK(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !styled {
		printf("  ✓ %s\n", msg)
		return
	}
	initStyles()
	printf("%s%s %s\n", indent, stGreen.Render("✓"), stInk.Render(msg))
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nerror: "+format+"\n\n", args...)
	os.Exit(1)
}
