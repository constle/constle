package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/constle/constle/internal/audit"
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
func printf(format string, args ...any) {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	fmt.Printf(format, args...)
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
		if len(os.Args) < 3 {
			die("usage: constle run <agentfile.yaml>")
		}
		if err := cmdRun(os.Args[2]); err != nil {
			die("%v", err)
		}

	case "validate":
		if len(os.Args) < 3 {
			die("usage: constle validate <agentfile.yaml>")
		}
		if err := cmdValidate(os.Args[2]); err != nil {
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

func cmdRun(agentfilePath string) error {
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
	printf("\n")

	printStep("detecting backend")

	backend, backendType, err := sandbox.DetectBestBackend(m.Sandbox.Isolation)
	if err != nil {
		return err
	}
	printOK("backend: %s", backendType)
	printf("\n")

	logPath := audit.DefaultLogPath(m.Identity.Name)
	logger, err := audit.New(logPath)
	if err != nil {
		return fmt.Errorf("cannot open audit log: %w", err)
	}
	defer logger.Close()

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

	// Squid logs must be read before Stop() removes the proxy container.
	defer func() {
		printStep("reading network audit logs...")
		if err := audit.FlushSquidLogs(
			runCtx.RunID,
			m.Identity.Name,
			runCtx.ProxyContainerID,
			logger,
		); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not read network logs: %v\n", err)
		} else {
			printOK("network events logged")
		}

		printf("\n")
		printStep("cleaning up containers...")
		if err := backend.Stop(runCtx); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: cleanup error: %v\n", err)
		} else {
			printOK("containers removed")
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
		exec.Command("docker", "stop", "--time=5", runCtx.AgentContainerID).Run()
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
				exec.Command("docker", "stop", "--time=5", runCtx.AgentContainerID).Run()
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
	printf("  isolation:   %s (inferred from capabilities)\n", m.Sandbox.Isolation)
	printf("  image:       %s\n", m.Sandbox.Image)
	printf("  memory:      %dMB\n", m.Sandbox.MemoryMB)

	if len(m.Sandbox.Network.AllowedHosts) > 0 {
		printf("  allowed:     %s\n",
			strings.Join(m.Sandbox.Network.AllowedHosts, ", "))
	}

	gates := manifest.InferRequiredGates(m.Capabilities)
	if len(gates) > 0 {
		printf("  human gates: %s (will require approval)\n",
			strings.Join(gates, ", "))
	}

	printf("\n")
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
  constle validate <agentfile>  check if an Agentfile is valid
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
