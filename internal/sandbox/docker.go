package sandbox

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/constle/constle/pkg/manifest"
)

// ============================================================
// docker.go — SandboxBackend implementation using Docker + Squid
//
// Two-network architecture:
//
//	[internet]
//	     |
//	constle-ext-{id}   ← external network (proxy only)
//	     |
//	constle-proxy-{id} ← Squid — connected to both networks
//	     |
//	constle-int-{id}   ← internal network (no direct internet access)
//	     |
//	constle-agent-{id} ← agent container — internal network only
//
// ============================================================

// DockerBackend implements SandboxBackend using Docker.
type DockerBackend struct{}

// Start creates two networks, starts the Squid proxy, and starts the agent container.
func (d *DockerBackend) Start(m *manifest.AgentManifest) (*RunContext, error) {
	// Remove any abandoned constle containers/networks from previous runs that
	// exited uncleanly (e.g. host reboot, SIGKILL). This is best-effort: if
	// Docker is unavailable the error is swallowed and we proceed normally.
	cleanupAbandoned()

	runID, err := newRunID()
	if err != nil {
		return nil, fmt.Errorf("cannot generate run ID: %w", err)
	}

	extNet := "constle-ext-" + runID
	intNet := "constle-int-" + runID
	proxyName := "constle-proxy-" + runID
	agentName := "constle-agent-" + runID

	squidConfigPath, err := writeSquidConfig(runID, m.Sandbox.Network.AllowedHosts)
	if err != nil {
		return nil, fmt.Errorf("cannot write Squid config: %w", err)
	}

	if err := dockerRun("network", "create", extNet); err != nil {
		os.Remove(squidConfigPath)
		return nil, fmt.Errorf("cannot create external network: %w", err)
	}

	if err := dockerRun("network", "create", "--internal", intNet); err != nil {
		dockerRun("network", "rm", extNet)
		os.Remove(squidConfigPath)
		return nil, fmt.Errorf("cannot create internal network: %w", err)
	}

	proxyID, err := startProxyContainer(proxyName, extNet, intNet, squidConfigPath)
	if err != nil {
		dockerRun("network", "rm", extNet)
		dockerRun("network", "rm", intNet)
		os.Remove(squidConfigPath)
		return nil, fmt.Errorf("cannot start proxy: %w", err)
	}

	if err := waitForSquid(proxyName); err != nil {
		dockerRun("stop", proxyName)
		dockerRun("rm", "-f", proxyName)
		dockerRun("network", "rm", extNet)
		dockerRun("network", "rm", intNet)
		os.Remove(squidConfigPath)
		return nil, fmt.Errorf("proxy did not start: %w", err)
	}

	image := m.Sandbox.Image
	if image == "" {
		image = "alpine:latest"
	}

	startTime := time.Now().UTC()
	agentLabels := map[string]string{
		"constle.managed":    "true",
		"constle.run-id":     runID,
		"constle.agent-name": m.Identity.Name,
		"constle.started-at": startTime.Format(time.RFC3339),
	}

	// Forward API keys from the host environment into the agent container.
	// Only included when the variable is set on the host; absent key → omitted flag.
	agentEnv := forwardedHostEnv()

	agentID, err := startAgentContainer(agentName, intNet, image, m.Sandbox.MemoryMB, m.Sandbox.Command, agentLabels, agentEnv)
	if err != nil {
		dockerRun("stop", proxyName)
		dockerRun("rm", "-f", proxyName)
		dockerRun("network", "rm", extNet)
		dockerRun("network", "rm", intNet)
		os.Remove(squidConfigPath)
		return nil, fmt.Errorf("cannot start agent: %w", err)
	}

	return &RunContext{
		RunID:               runID,
		AgentName:           m.Identity.Name,
		Backend:             BackendDocker,
		AgentContainerID:    agentID,
		ProxyContainerID:    proxyID,
		NetworkName:         intNet,
		SquidConfigPath:     squidConfigPath,
		StartTime:           startTime,
		IsolationLevel:      string(m.Sandbox.Isolation),
		externalNetworkName: extNet,
	}, nil
}

// Wait blocks until the agent container exits and returns its exit code.
func (d *DockerBackend) Wait(ctx *RunContext) (int, error) {
	out, err := exec.Command("docker", "wait", ctx.AgentContainerID).Output()
	if err != nil {
		return -1, fmt.Errorf("docker wait failed: %w", err)
	}
	exitCode, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return -1, fmt.Errorf("cannot parse exit code: %w", err)
	}
	return exitCode, nil
}

// Kill gracefully stops the agent container (SIGTERM, then SIGKILL after
// 5 seconds) without cleaning up resources — Wait unblocks and the normal
// Stop path still runs.
func (d *DockerBackend) Kill(ctx *RunContext) error {
	return dockerRun("stop", "--time=5", ctx.AgentContainerID)
}

// Stop removes all containers and networks for this run.
func (d *DockerBackend) Stop(ctx *RunContext) error {
	var errs []string

	for _, name := range []string{ctx.AgentContainerID, ctx.ProxyContainerID} {
		if err := dockerRun("stop", "--time=5", name); err != nil {
			errs = append(errs, fmt.Sprintf("stop %s: %v", name, err))
		}
		if err := dockerRun("rm", "-f", name); err != nil {
			errs = append(errs, fmt.Sprintf("rm %s: %v", name, err))
		}
	}

	for _, net := range []string{ctx.NetworkName, ctx.externalNetworkName} {
		if net != "" {
			if err := dockerRun("network", "rm", net); err != nil {
				errs = append(errs, fmt.Sprintf("rm network %s: %v", net, err))
			}
		}
	}

	if ctx.SquidConfigPath != "" {
		os.Remove(ctx.SquidConfigPath)
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Logs returns the combined stdout+stderr of the agent container.
func (d *DockerBackend) Logs(ctx *RunContext) ([]byte, error) {
	out, err := exec.Command("docker", "logs", ctx.AgentContainerID).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker logs: %w", err)
	}
	return out, nil
}

func writeSquidConfig(runID string, allowedHosts []string) (string, error) {
	config := buildSquidConfig(runID, allowedHosts, "3128", "/var/log/squid/access.log", "")
	path := filepath.Join(os.TempDir(), "constle-squid-"+runID+".conf")
	return path, os.WriteFile(path, []byte(config), 0644)
}

// buildSquidConfig renders the allowlist-enforcing Squid configuration
// shared by both backends. httpPort is either a bare port (Docker: Squid
// listens inside its own container) or "ip:port" (Firecracker: Squid runs
// on the host and must bind only the per-run TAP gateway address). extra
// appends backend-specific directives.
func buildSquidConfig(runID string, allowedHosts []string, httpPort, accessLogPath, extra string) string {
	var config string
	if len(allowedHosts) > 0 {
		hosts := strings.Join(allowedHosts, " ")
		config = fmt.Sprintf(`# Constle - run %s
acl allowed_hosts dstdomain %s

# Block direct IP connections to prevent allowlist bypass.
acl ip_only dst 0.0.0.0/0
http_access deny ip_only !allowed_hosts

http_access allow allowed_hosts
http_access allow CONNECT allowed_hosts
http_access deny all

http_port %s
cache deny all
access_log %s
cache_log /dev/null
coredump_dir /tmp
`, runID, hosts, httpPort, accessLogPath)
	} else {
		config = fmt.Sprintf(`# Constle - run %s - no network
http_access deny all
http_port %s
cache deny all
access_log %s
cache_log /dev/null
coredump_dir /tmp
`, runID, httpPort, accessLogPath)
	}

	if extra != "" {
		config += extra + "\n"
	}
	return config
}

// forwardedHostEnv collects the host environment variables forwarded into
// every agent sandbox, regardless of backend. Only variables actually set
// on the host are included.
func forwardedHostEnv() map[string]string {
	env := map[string]string{}
	for _, key := range []string{"ANTHROPIC_API_KEY", "GROQ_API_KEY", "AGENT_TASK"} {
		if value := os.Getenv(key); value != "" {
			env[key] = value
		}
	}
	return env
}

func startProxyContainer(name, extNet, intNet, configPath string) (string, error) {
	out, err := exec.Command("docker", "run", "-d",
		"--name", name,
		"--network", extNet,
		"-v", configPath+":/etc/squid/squid.conf:ro",
		"ubuntu/squid:latest",
	).Output()
	if err != nil {
		return "", fmt.Errorf("docker run proxy: %w", err)
	}
	proxyID := strings.TrimSpace(string(out))

	if err := dockerRun("network", "connect", "--alias", "squid", intNet, proxyID); err != nil {
		return "", fmt.Errorf("cannot connect proxy to internal network: %w", err)
	}
	return proxyID, nil
}

// waitForSquid polls until the proxy container actually LISTENs on 3128.
// `squid -k check` is not enough: it passes as soon as the PID file exists,
// which is before the listener is up — the agent would then get an instant
// connection refused. /proc/net/tcp is readable in any container and shows
// the authoritative socket state.
func waitForSquid(proxyName string) error {
	for i := 0; i < 30; i++ {
		out, err := exec.Command("docker", "exec", proxyName,
			"sh", "-c", "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null").Output()
		if err == nil && hasListenerOnPort(string(out), 3128) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("squid did not become ready after 15s")
}

// hasListenerOnPort reports whether a /proc/net/tcp dump contains a socket
// in LISTEN state (st == 0A) whose local address ends with the given port.
func hasListenerOnPort(procNetTCP string, port int) bool {
	suffix := fmt.Sprintf(":%04X", port)
	for _, line := range strings.Split(procNetTCP, "\n") {
		fields := strings.Fields(line)
		// sl local_address rem_address st ...
		if len(fields) >= 4 && strings.HasSuffix(fields[1], suffix) && fields[3] == "0A" {
			return true
		}
	}
	return false
}

func startAgentContainer(name, intNet, image string, memoryMB int, command []string, labels map[string]string, envVars map[string]string) (string, error) {
	if memoryMB == 0 {
		memoryMB = 512
	}
	args := []string{"run", "-d",
		"--name", name,
		"--network", intNet,
		fmt.Sprintf("--memory=%dm", memoryMB),
		fmt.Sprintf("--memory-swap=%dm", memoryMB),
		"-e", "HTTP_PROXY=http://squid:3128",
		"-e", "HTTPS_PROXY=http://squid:3128",
		"-e", "http_proxy=http://squid:3128",
		"-e", "https_proxy=http://squid:3128",
	}

	// Caller-supplied env vars (e.g. ANTHROPIC_API_KEY forwarded from the host).
	for k, v := range envVars {
		args = append(args, "-e", k+"="+v)
	}

	for k, v := range labels {
		args = append(args, "--label", k+"="+v)
	}

	args = append(args, image)
	args = append(args, command...)

	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		return "", fmt.Errorf("docker run agent: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func dockerRun(args ...string) error {
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("docker %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func newRunID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// cleanupAbandoned removes Docker resources left behind by constle runs that
// ended without a clean Stop() — e.g. host reboot, process kill, or a crash
// after the container exited but before the defer ran.
//
// Strategy: list all constle-labelled containers in exited or dead state, group
// by run_id (both agent and proxy share the same label), then rm -f the pair
// and their two networks. Silent on all errors — this is housekeeping, not a
// critical path.
func cleanupAbandoned() {
	out, err := exec.Command("docker", "ps", "-a",
		"--filter", "label=constle.managed=true",
		"--filter", "status=exited",
		"--filter", "status=dead",
		"--format", "{{json .}}",
	).Output()
	if err != nil {
		return
	}

	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var c struct {
			Labels string `json:"Labels"`
		}
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue
		}
		runID := labelValue(c.Labels, "constle.run-id")
		if runID == "" || seen[runID] {
			continue
		}
		seen[runID] = true

		for _, name := range []string{"constle-agent-" + runID, "constle-proxy-" + runID} {
			exec.Command("docker", "rm", "-f", name).Run()
		}
		for _, net := range []string{"constle-int-" + runID, "constle-ext-" + runID} {
			exec.Command("docker", "network", "rm", net).Run()
		}
	}
}

// labelValue extracts a single value from Docker's comma-separated label string
// ("key1=val1,key2=val2,..."). Returns "" if the key is absent.
func labelValue(labelsStr, key string) string {
	for _, pair := range strings.Split(labelsStr, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) == 2 && parts[0] == key {
			return parts[1]
		}
	}
	return ""
}
