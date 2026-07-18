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

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	switch os.Args[1] {

	case "init":
		if err := cmdInit(); err != nil {
			die("%v", err)
		}

	case "run":
		agentfile, backendOverride, err := parseRunArgs(os.Args[2:])
		if err != nil {
			die("%v", err)
		}
		if err := cmdRun(agentfile, backendOverride); err != nil {
			die("%v", err)
		}

	case "validate":
		if len(os.Args) < 3 {
			die("usage: constle validate <agentfile.yaml>")
		}
		if err := cmdValidate(os.Args[2]); err != nil {
			die("%v", err)
		}

	case "identity":
		if err := cmdIdentity(os.Args[2:]); err != nil {
			die("%v", err)
		}

	case "audit":
		if len(os.Args) < 3 || os.Args[2] != "verify" {
			die("usage: constle audit verify [--did=<did:key:…>] <logfile>")
		}
		logPath, expectedDID, err := parseAuditVerifyArgs(os.Args[3:])
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
		if len(os.Args) < 3 {
			die("usage: constle stop <run_id>")
		}
		if err := cmdStop(os.Args[2]); err != nil {
			die("%v", err)
		}

	case "version":
		fmt.Printf("constle v%s\n", constleVersion)

	case "help", "--help", "-h":
		printHelp()

	default:
		die("unknown command %q\nrun 'constle help' for usage", os.Args[1])
	}
}

// parseRunArgs extracts the Agentfile path and the optional --backend flag
// from `constle run` arguments.
func parseRunArgs(args []string) (agentfile, backendOverride string, err error) {
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--backend="):
			backendOverride = strings.TrimPrefix(arg, "--backend=")
		case strings.HasPrefix(arg, "-"):
			return "", "", fmt.Errorf("unknown flag %q\nusage: constle run [--backend=docker|firecracker] <agentfile.yaml>", arg)
		case agentfile == "":
			agentfile = arg
		default:
			return "", "", fmt.Errorf("unexpected argument %q", arg)
		}
	}
	if agentfile == "" {
		return "", "", fmt.Errorf("usage: constle run [--backend=docker|firecracker] <agentfile.yaml>")
	}
	return agentfile, backendOverride, nil
}

func cmdRun(agentfilePath, backendOverride string) error {
	printf("\nconstle v%s\n\n", constleVersion)

	printStep("parsing %s", agentfilePath)

	m, err := manifest.ParseFile(agentfilePath)
	if err != nil {
		return fmt.Errorf("cannot parse Agentfile: %w", err)
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("invalid Agentfile: %w", err)
	}
	printOK("Agentfile valid")

	printf("     agent:     %s v%s\n", m.Identity.Name, m.Identity.Version)
	printf("     isolation: %s\n", m.Sandbox.Isolation)
	printf("     memory:    %dMB\n", m.Sandbox.MemoryMB)
	if len(m.Sandbox.Network.AllowedHosts) > 0 {
		printf("     network:   restricted → %s\n",
			strings.Join(m.Sandbox.Network.AllowedHosts, ", "))
	}
	if m.Limits.MaxDurationSeconds > 0 {
		printf("     max_duration: %ds\n", m.Limits.MaxDurationSeconds)
	}
	if len(m.MCP.Servers) > 0 {
		ids := make([]string, len(m.MCP.Servers))
		for i, srv := range m.MCP.Servers {
			ids[i] = srv.ID
		}
		printf("     mcp:       %s (via gate proxy)\n", strings.Join(ids, ", "))
	}
	if len(m.A2A.Peers) > 0 {
		names := make([]string, len(m.A2A.Peers))
		for i, p := range m.A2A.Peers {
			names[i] = p.Name
		}
		printf("     a2a:       %s (signed via host gate)\n", strings.Join(names, ", "))
	}
	printf("\n")

	warnUnenforcedHumanGates(m)

	printStep("detecting backend")

	backend, backendType, err := sandbox.DetectBestBackend(m.Sandbox.Isolation, backendOverride)
	if err != nil {
		return err
	}
	printOK("backend: %s", backendType)
	printf("\n")

	logPath := audit.DefaultLogPath(m.Identity.Name)

	// Fail closed on identity: when the Agentfile declares identity.did,
	// every audit entry must be signed with the matching local key — running
	// unsigned while the manifest promises a signed log would make the
	// declared protection a lie (same principle as warnUnenforcedHumanGates).
	// The loaded identity also signs outbound A2A calls, so it is kept for
	// the A2A gate below.
	var runIdentity *identity.Identity
	var logger *audit.Logger
	if m.Identity.DID != "" {
		runIdentity, err = loadRunIdentity(m)
		if err != nil {
			return err
		}
		logger, err = audit.NewSigned(logPath, runIdentity)
		if err != nil {
			return fmt.Errorf("cannot open signed audit log: %w", err)
		}
		printOK("identity: %s", runIdentity.DID())
		printf("     audit log entries are Ed25519-signed and hash-chained\n\n")
	} else {
		var err error
		logger, err = audit.New(logPath)
		if err != nil {
			return fmt.Errorf("cannot open audit log: %w", err)
		}
	}
	defer logger.Close()

	if m.Identity.DID != "" && !logger.Signed() {
		// Unreachable by construction; guards against future refactors ever
		// letting a declared identity run with an unsigned log.
		return fmt.Errorf("internal error: identity.did is declared but the audit logger is not signing — refusing to run")
	}

	// Human-gate enforcement: every declared MCP server is reachable from
	// the sandbox only through this gate proxy, which pauses gated tool
	// calls for approval. The gate lives in this process — it owns the
	// terminal the approve/deny prompt needs.
	var gate *mcpgate.Gate
	if len(m.MCP.Servers) > 0 {
		approver := mcpgate.NewTerminalApprover(lockedStdout{})

		var notifier mcpgate.Notifier
		if wn := mcpgate.NewWebhookNotifier(m.HumanGates, lockedStdout{}); wn != nil {
			notifier = wn
		}

		gate, err = mcpgate.New(m, approver, notifier, logger)
		if err != nil {
			return fmt.Errorf("cannot build MCP gate: %w", err)
		}
		defer gate.Close()

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
		defer a2aGate.Close()

		if setter, ok := backend.(sandbox.A2AGateSetter); ok {
			setter.SetA2AGate(a2aGate)
		} else {
			// Fail closed: never run declared A2A peers without the signing gate.
			return fmt.Errorf("backend %s does not support the A2A gate", backendType)
		}
	}

	// DockerBackend.Start() silently removes any abandoned constle containers
	// (exited/dead state) before allocating new resources.
	printStep("starting sandbox...")

	startTime := time.Now()

	runCtx, err := backend.Start(m)
	if err != nil {
		logger.Log("", m.Identity.Name, audit.EventRunFailed,
			map[string]any{"error": err.Error()})
		return fmt.Errorf("cannot start sandbox: %w", err)
	}

	// Squid logs must be read before Stop() removes the proxy container
	// (Docker) or the run directory (Firecracker).
	defer func() {
		printStep("reading network audit logs...")
		var flushErr error
		if runCtx.SquidAccessLog != "" {
			flushErr = audit.FlushSquidLogFile(runCtx.RunID, m.Identity.Name, runCtx.SquidAccessLog, logger)
		} else {
			flushErr = audit.FlushSquidLogs(runCtx.RunID, m.Identity.Name, runCtx.ProxyContainerID, logger)
		}
		if flushErr != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not read network logs: %v\n", flushErr)
		} else {
			printOK("network events logged")
		}

		printf("\n")
		printStep("cleaning up sandbox...")
		if err := backend.Stop(runCtx); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: cleanup error: %v\n", err)
		} else {
			printOK("sandbox removed")
		}
	}()

	logger.LogWithIsolation(
		runCtx.RunID, m.Identity.Name,
		audit.EventRunStarted,
		string(m.Sandbox.Isolation),
		map[string]any{
			"backend": string(backendType),
			"image":   m.Sandbox.Image,
		},
	)

	printOK("sandbox started (run_id: %s)", runCtx.RunID)

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
				backend.Kill(runCtx)
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
		backend.Kill(runCtx)
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
				backend.Kill(runCtx)
			case <-userStopped:
				// User stopped first; let the signal goroutine handle cleanup.
			}
		}()
	}

	printf("\n  ┌─ agent output ──────────────────────────\n")

	exitCode, waitErr := backend.Wait(runCtx)

	if logs, logsErr := backend.Logs(runCtx); logsErr == nil && len(logs) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(logs)), "\n") {
			if line != "" {
				printf("  │ %s\n", line)
			}
		}
	}

	printf("  └─────────────────────────────────────────\n\n")

	duration := time.Since(startTime).Round(time.Millisecond)

	select {
	case <-limitReached:
		logger.Log(runCtx.RunID, m.Identity.Name, audit.EventTerminatedByLimit,
			map[string]any{
				"limit_seconds": m.Limits.MaxDurationSeconds,
				"duration":      duration.String(),
			})
		printf("⚑ agent terminated: duration limit (%ds) exceeded    duration=%s\n",
			m.Limits.MaxDurationSeconds, duration)
		printf("  audit log: %s\n\n", logPath)
		return fmt.Errorf("agent terminated: duration limit exceeded")
	default:
	}

	select {
	case <-gateAborted:
		// The gate itself already logged the gate_timeout event; this entry
		// records the run-level consequence.
		logger.Log(runCtx.RunID, m.Identity.Name, audit.EventRunFailed,
			map[string]any{
				"reason":   "human_gate_timeout_abort",
				"duration": duration.String(),
			})
		printf("⚑ agent terminated: human gate timed out without approval (on_timeout: abort)    duration=%s\n", duration)
		printf("  audit log: %s\n\n", logPath)
		return fmt.Errorf("agent terminated: human gate timed out without approval")
	default:
	}

	select {
	case <-userStopped:
		logger.Log(runCtx.RunID, m.Identity.Name, audit.EventRunFailed,
			map[string]any{
				"reason":   "stopped_by_user",
				"duration": duration.String(),
			})
		printf("⚑ agent stopped by user    duration=%s\n", duration)
		printf("  audit log: %s\n\n", logPath)
		return nil
	default:
	}

	if waitErr != nil || exitCode != 0 {
		logger.Log(runCtx.RunID, m.Identity.Name, audit.EventRunFailed,
			map[string]any{
				"exit_code": exitCode,
				"duration":  duration.String(),
			})
		printf("✗ run failed    exit=%d    duration=%s\n", exitCode, duration)
		printf("  audit log: %s\n\n", logPath)
		return fmt.Errorf("agent exited with code %d", exitCode)
	}

	logger.Log(runCtx.RunID, m.Identity.Name, audit.EventRunFinished,
		map[string]any{
			"exit_code": 0,
			"duration":  duration.String(),
		})
	printf("✓ run finished    exit=0    duration=%s\n", duration)
	printf("  audit log: %s\n\n", logPath)

	return nil
}

func cmdValidate(agentfilePath string) error {
	m, err := manifest.ParseFile(agentfilePath)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	printf("✓ %s is valid\n\n", agentfilePath)
	printf("  name:        %s\n", m.Identity.Name)
	printf("  version:     %s\n", m.Identity.Version)
	if m.Identity.DID != "" {
		printf("  did:         %s\n", m.Identity.DID)
	}
	printf("  isolation:   %s (inferred from capabilities)\n", m.Sandbox.Isolation)
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
	warnUnenforcedHumanGates(m)
	warnUnverifiableIdentity(m)
	return nil
}

// ============================================================
// Helper functions
// ============================================================

func printHelp() {
	fmt.Printf(`constle v%s — AI agent runtime

usage:
  constle init                  create agent.yaml with sensible defaults
  constle run <agentfile>       run an agent in a sandbox
    --backend=<name>            force a backend: docker or firecracker
  constle validate <agentfile>  check if an Agentfile is valid
  constle identity create <name>  create a cryptographic agent identity (did:key)
    --owner=<email>             bind the identity to an owner
  constle identity show <name>  show an agent's DID and key location
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
	printf("  → "+format+"\n", args...)
}

func printOK(format string, args ...any) {
	printf("  ✓ "+format+"\n", args...)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nerror: "+format+"\n\n", args...)
	os.Exit(1)
}
