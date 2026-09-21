package sandbox

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/constle/constle/internal/agentenv"
	"github.com/constle/constle/pkg/manifest"
)

// Secrets a real run forwards into the agent container. The gate tokens are
// deliberately not standalone variables: mcpGateEnv and a2aGateEnv embed the
// token in the gate URL, which is precisely the value that used to sit in the
// argv, so the test builds them through those functions rather than
// hand-writing a name that could drift from the production one.
const (
	hostAPIKey   = "sk-ant-SECRETVALUE-anthropic"
	hostGroqKey  = "gsk-SECRETVALUE-groq"
	hostTask     = "SECRETVALUE-agent-task"
	mcpGateToken = "SECRETVALUE-mcp-gate-token"
	a2aGateToken = "SECRETVALUE-a2a-gate-token"
)

// realAgentEnv assembles the forwarded environment exactly as
// DockerBackend.Start does, so an assertion over it covers the real variable
// names and the real URL shapes.
//
// The three host variables are DECLARED here, because that is now the only way
// one reaches a sandbox. They used to arrive from a hardcoded list inside the
// backend, which is what made every key the operator had part of every agent's
// environment; the manifest below is the per-agent replacement for that list.
func realAgentEnv(t *testing.T) map[string]string {
	t.Helper()
	t.Setenv("ANTHROPIC_API_KEY", hostAPIKey)
	t.Setenv("GROQ_API_KEY", hostGroqKey)
	t.Setenv("AGENT_TASK", hostTask)

	m := &manifest.AgentManifest{}
	m.MCP.Servers = []manifest.MCPServer{{ID: "email-svc"}}
	m.Credentials = []manifest.Credential{
		{Name: "ANTHROPIC_API_KEY"},
		{Name: "GROQ_API_KEY"},
		{Name: "AGENT_TASK"},
	}

	credEnv, err := agentenv.Resolve(m)
	if err != nil {
		t.Fatalf("credentials.Resolve: %v", err)
	}

	env := map[string]string{}
	for k, v := range credEnv {
		env[k] = v
	}
	for k, v := range mcpGateEnv(m, "172.17.0.1", 7800, mcpGateToken) {
		env[k] = v
	}
	for k, v := range a2aGateEnv("172.17.0.1", 7801, a2aGateToken) {
		env[k] = v
	}
	return env
}

// secretValues returns every value in env that must never reach an argv,
// keyed by the variable that carries it.
func secretValues(env map[string]string) map[string]string {
	secrets := map[string]string{}
	for k, v := range env {
		for _, s := range []string{hostAPIKey, hostGroqKey, hostTask, mcpGateToken, a2aGateToken} {
			if strings.Contains(v, s) {
				secrets[k] = s
			}
		}
	}
	return secrets
}

// TestAgentRunArgsCarryNoSecretValues is the regression guard for the argv
// half of the world-readable-secrets finding.
//
// The backend used to spell forwarded variables as `-e KEY=VALUE`. That put
// the operator's API keys and both gate tokens into the argv of the docker
// client process, and /proc/<pid>/cmdline is world-readable — any
// unprivileged local user running `ps auxww`, or polling /proc while a
// container started, read them straight out. The fix passes the name alone
// and lets the client resolve the value from its own environment, which
// /proc exposes only to the process owner.
//
// This test fails on the pre-fix argv: it searches for the values, not for
// the old spelling, so it cannot be satisfied by a different way of writing
// the secret into the command line.
func TestAgentRunArgsCarryNoSecretValues(t *testing.T) {
	env := realAgentEnv(t)
	secrets := secretValues(env)
	if len(secrets) != 5 {
		t.Fatalf("expected 5 secret-bearing variables, got %d (%v) — the test is not covering what it claims", len(secrets), secrets)
	}

	args := agentRunArgs("constle-agent-deadbeef", "constle-int-deadbeef",
		"alpine:latest", 0, []string{"sh", "-c", "id"},
		map[string]string{"constle.managed": "true", "constle.run-id": "deadbeef"},
		env)

	joined := strings.Join(args, "\x00")
	for name, value := range secrets {
		if strings.Contains(joined, value) {
			t.Errorf("%s's value is present in the docker argv, which /proc/<pid>/cmdline publishes to every local user\nargv: %v", name, args)
		}
		// The variable must still reach the container — by name.
		if !hasOptionArg(args, "-e", name) {
			t.Errorf("%s is not passed to the container at all: expected `-e %s` with no value\nargv: %v", name, name, args)
		}
	}
}

// TestAgentEnvForCommandCarriesTheValues is the other half: `-e NAME` only
// works if the docker client's own environment actually holds NAME, so a
// name-only argv with an environment that dropped the variable would mean
// the agent silently runs without its API key.
func TestAgentEnvForCommandCarriesTheValues(t *testing.T) {
	agentEnv := realAgentEnv(t)
	env := agentEnvForCommand(agentEnv)

	for name, value := range agentEnv {
		count, got := envValueOnce(env, name)
		switch {
		case count == 0:
			t.Errorf("%s is absent from the docker client environment; `-e %s` would pass nothing", name, name)
		case count > 1:
			t.Errorf("%s appears %d times in the docker client environment; which entry wins is then a property of the exec path rather than of this code", name, count)
		case got != value:
			t.Errorf("%s = %q in the docker client environment, want %q", name, got, value)
		}
	}

	// The parent environment must survive: docker needs DOCKER_HOST, PATH and
	// HOME (for ~/.docker/config.json) to reach the daemon at all.
	for _, keep := range os.Environ() {
		name, _, ok := strings.Cut(keep, "=")
		if !ok || agentEnv[name] != "" {
			continue
		}
		if !hasEnvEntry(env, keep) {
			t.Errorf("parent environment entry %s was dropped; docker may lose DOCKER_HOST/PATH/HOME", name)
			break
		}
	}
}

// TestAgentEnvForCommandReplacesInheritedValue pins what makes the forwarded
// value authoritative: the inherited entry must be GONE, not merely outranked.
//
// The operator's shell exports ANTHROPIC_API_KEY, so os.Environ() already
// carries it. Sharper still, the run always forwards gate URLs the shell has
// no legitimate reason to hold — if an inherited CONSTLE_A2A_URL survived in
// the environment next to the minted one, whether the agent reaches its gate
// or some other endpoint would come down to whose duplicate-key rule applies.
//
// The assertion is exactly-once, so it holds without appealing to any such
// rule. It fails against an implementation that appends the forwarded value
// without first removing the inherited one, because the count is then 2.
func TestAgentEnvForCommandReplacesInheritedValue(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-INHERITED-wrong")
	t.Setenv("CONSTLE_A2A_URL", "http://inherited.example/not-the-gate")

	want := map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-FORWARDED-right",
		"CONSTLE_A2A_URL":   "http://172.17.0.1:7801/minted-gate-token",
	}
	env := agentEnvForCommand(want)

	for name, value := range want {
		count, got := envValueOnce(env, name)
		if count != 1 {
			t.Errorf("%s appears %d times, want exactly 1 — the inherited entry was not removed", name, count)
		}
		if got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

// TestAgentRunArgsKeepProxyValuesInline guards the deliberate exception: the
// four proxy variables address the in-network Squid and are not secret, so
// they keep their values in the argv. If they were ever switched to name-only
// without being added to the client environment, egress would leave the
// container unproxied — a far worse failure than a visible argv.
// Not a regression test: it guards a deliberate non-change, so it passes
// against the pre-fix argv too.
func TestAgentRunArgsKeepProxyValuesInline(t *testing.T) {
	args := agentRunArgs("a", "n", "img", 0, []string{"sh"}, nil, realAgentEnv(t))
	for _, want := range []string{
		"HTTP_PROXY=http://squid:3128",
		"HTTPS_PROXY=http://squid:3128",
		"http_proxy=http://squid:3128",
		"https_proxy=http://squid:3128",
	} {
		if !hasOptionArg(args, "-e", want) {
			t.Errorf("proxy variable %q is missing from the argv; the agent would egress unproxied\nargv: %v", want, args)
		}
	}
}

// envValueOnce returns how many times name appears in a KEY=VALUE slice and
// the value of the last such entry.
//
// Callers assert on the count, not on a tie-break. A helper that scanned for
// the last match would be asserting its own precedence rule rather than the
// environment the docker client is handed: it would pass whether or not the
// appended entry actually wins, on any platform and through any exec path.
// With exactly one entry per key there is no precedence left to get wrong.
func envValueOnce(env []string, name string) (count int, got string) {
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == name {
			count++
			got = v
		}
	}
	return count, got
}

func hasEnvEntry(env []string, want string) bool {
	for _, e := range env {
		if e == want {
			return true
		}
	}
	return false
}

// TestAgentRunCommandDeliversValuesToTheChild closes the gap that let the two
// halves of the fix be individually correct and jointly useless.
//
// `-e NAME` with no "=" means "look NAME up in your own environment". If the
// argv says that and the command's Env does not carry NAME, docker sets
// nothing in the container AND exits 0 — no error anywhere. The API keys would
// survive on plain inheritance from the operator's shell, so the visible
// symptom would be only that CONSTLE_MCP_<ID>_URL and CONSTLE_A2A_URL, which
// are minted per run and exist in no shell, quietly vanish: an agent running
// with no route to its gate.
//
// Asserting on cmd.Env alone would not catch that, because it is the exec that
// delivers the value. So this takes the command the production path builds and
// runs it — with docker swapped for a probe that prints its own environment —
// proving the values reach a real child process.
//
// It fails against a backend that builds the argv and the environment
// separately: neutering the Env assignment leaves every other test green.
func TestAgentRunCommandDeliversValuesToTheChild(t *testing.T) {
	env := realAgentEnv(t)
	secrets := secretValues(env)

	cmd := agentRunCommand("constle-agent-deadbeef", "constle-int-deadbeef",
		"alpine:latest", 0, []string{"sh", "-c", "id"},
		map[string]string{"constle.managed": "true"}, env)

	// Every forwarded variable must be named in the argv...
	for name := range env {
		if !hasOptionArg(cmd.Args, "-e", name) {
			t.Fatalf("%s is not named in the argv; the environment below would never be consulted\nargv: %v", name, cmd.Args)
		}
	}

	// ...and must survive an actual exec. Keep the environment the production
	// path built; replace only the program, so what is under test is the
	// command object itself.
	probe := exec.Command("/bin/sh", "-c", `for n in "$@"; do printf '%s=%s\n' "$n" "$(eval echo \$$n)"; done`, "sh")
	for name := range env {
		probe.Args = append(probe.Args, name)
	}
	probe.Env = cmd.Env

	out, err := probe.Output()
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	seen := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			seen[k] = v
		}
	}
	for name, want := range env {
		if seen[name] != want {
			t.Errorf("child process saw %s=%q, want %q — the value never reached the command", name, seen[name], want)
		}
	}
	// And the secrets still must not be in the argv that carried them there.
	joined := strings.Join(cmd.Args, "\x00")
	for name, secret := range secrets {
		if strings.Contains(joined, secret) {
			t.Errorf("%s's value is in the argv of the command actually executed\nargv: %v", name, cmd.Args)
		}
	}
}

// TestAgentRunCommandReachesTheContainer is the same guarantee end to end,
// against the real daemon: the container must receive the value, and the
// docker client's argv must not contain it.
func TestAgentRunCommandReachesTheContainer(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("Docker not available")
	}
	env := realAgentEnv(t)

	cmd := agentRunCommand("unused", "none", "alpine:latest", 0,
		[]string{"sh", "-c", "printf %s \"$CONSTLE_A2A_URL\""}, nil, env)

	// `docker run --rm` without -d, so the output is the container's and
	// nothing survives the test. Everything else is what production builds.
	args := cmd.Args[1:]
	if args[0] != "run" || args[1] != "-d" {
		t.Fatalf("argv does not begin with \"run\" \"-d\": %v", args)
	}
	run := append([]string{"run", "--rm"}, args[2:]...)
	run = removeOptionArg(run, "--name", "unused")

	probe := exec.Command("docker", run...)
	probe.Env = cmd.Env

	// Stdout only. The container's output is on stdout; the docker client's own
	// diagnostics are on stderr, and on a runner without the image cached those
	// diagnostics are a pull progress report that CombinedOutput would prepend
	// to the value being asserted on. What the container received must not
	// depend on what the client had to say about fetching the image first.
	var clientErr bytes.Buffer
	probe.Stderr = &clientErr
	out, err := probe.Output()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, clientErr.Bytes())
	}

	want := env["CONSTLE_A2A_URL"]
	if got := strings.TrimSpace(string(out)); got != want {
		t.Errorf("container received CONSTLE_A2A_URL=%q, want %q — `-e NAME` resolved to nothing", got, want)
	}
	if strings.Contains(strings.Join(probe.Args, "\x00"), a2aGateToken) {
		t.Errorf("the gate token is in the docker client's argv\nargv: %v", probe.Args)
	}
}

// removeOptionArg drops a "--flag value" pair from an argv.
func removeOptionArg(args []string, flag, value string) []string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return append(append([]string{}, args[:i]...), args[i+2:]...)
		}
	}
	return args
}
