package sandbox

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAgentRunArgsEndOptionsBeforeImage pins the "--" that separates the
// docker run options from the image and command. Both come from the
// Agentfile, and without the separator an image spelled like an option was
// parsed as one: `image: "-v"` with `command: ["/:/host", "alpine", "sh"]`
// became `docker run ... -v /:/host alpine sh`, a sandbox with the host
// filesystem mounted inside it. With "--" in place the same manifest is read
// as IMAGE="-v", which docker refuses as an invalid reference.
//
// This fails on the argv the backend built before the separator existed,
// where the image followed the last --label directly.
func TestAgentRunArgsEndOptionsBeforeImage(t *testing.T) {
	command := []string{"/:/host", "alpine:latest", "sh", "-c", "id"}
	labels := map[string]string{"constle.managed": "true", "constle.run-id": "deadbeef"}
	env := map[string]string{"ANTHROPIC_API_KEY": "sk-test"}

	for _, image := range []string{"-v", "--privileged", "--network=host", "--", "-", "alpine:latest"} {
		args := agentRunArgs("constle-agent-deadbeef", "constle-int-deadbeef", image, 0, command, labels, env)

		sep := argIndex(args, "--")
		if sep < 0 {
			t.Errorf("image %q: argv has no \"--\" before the image, so it is parsed as a docker run option\ngot: %v", image, args)
			continue
		}

		// Everything after the separator must be exactly IMAGE then COMMAND,
		// in order: that is what docker reads as positionals once options end.
		want := append([]string{image}, command...)
		if got := args[sep+1:]; strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("image %q: after \"--\" = %q, want image then command %q", image, got, want)
		}

		// And every option must sit before it: an option placed after "--" is
		// handed to the container as its command instead of taking effect.
		for _, opt := range []string{"--name", "--network", "--memory=512m", "--memory-swap=512m"} {
			if i := argIndex(args, opt); i < 0 || i > sep {
				t.Errorf("image %q: option %s must precede \"--\" (found at %d, separator at %d)\ngot: %v", image, opt, i, sep, args)
			}
		}
		if !hasOptionArg(args[:sep], "-e", "ANTHROPIC_API_KEY=sk-test") {
			t.Errorf("image %q: forwarded env var is missing before \"--\"\ngot: %v", image, args)
		}
		for key, val := range labels {
			if !hasLabelArg(args[:sep], key+"="+val) {
				t.Errorf("image %q: --label %s=%s is missing before \"--\"\ngot: %v", image, key, val, args)
			}
		}
	}
}

// TestAgentRunArgsRefusedByDockerForOptionLikeImage runs the exact argv the
// backend builds through the real docker CLI, with `create` in place of
// `run -d` so nothing is ever started, and asserts that docker refuses the
// option-shaped image outright. Before the "--" was added this same argv
// created a container from alpine:latest with the host root bind-mounted at
// /host; the cleanup removes such a container so a regression cannot leave
// one behind.
func TestAgentRunArgsRefusedByDockerForOptionLikeImage(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("Docker not available")
	}
	id, err := newRunID()
	if err != nil {
		t.Fatal(err)
	}
	name := "constle-argv-regression-" + id
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	args := agentRunArgs(name, "none", "-v", 0,
		[]string{"/:/host", "alpine:latest", "sh", "-c", "ls /host"},
		map[string]string{"constle.managed": "true", "constle.run-id": id}, nil)

	// `docker create` takes every option this argv uses and only creates the
	// container; -d is the one option it lacks, so it is dropped. If the guard
	// ever fails the result is a stopped container to remove, not a running
	// one with the host mounted.
	if len(args) < 2 || args[0] != "run" || args[1] != "-d" {
		t.Fatalf("argv does not begin with \"run\" \"-d\": %v", args)
	}
	create := append([]string{"create"}, args[2:]...)

	out, err := exec.Command("docker", create...).CombinedOutput()
	if err == nil {
		t.Fatalf("docker accepted an option-shaped image and created a container\nargv: %v\nout: %s", create, out)
	}
	if !strings.Contains(string(out), "invalid reference format") {
		t.Errorf("docker create failed, but not because \"-v\" is an invalid image reference:\n%s", out)
	}
	if exec.Command("docker", "inspect", name).Run() == nil {
		t.Errorf("container %s exists although docker refused the argv", name)
	}
}

// TestAgentRunArgsAreDeterministic guards the key sort in agentRunArgs, for
// the same reason as TestProxyRunArgsAreDeterministic: randomised map
// iteration would make the argv, and any assertion on it, vary run to run.
func TestAgentRunArgsAreDeterministic(t *testing.T) {
	labels := map[string]string{"constle.managed": "true", "constle.run-id": "abc", "constle.agent-name": "x", "constle.started-at": "t"}
	env := map[string]string{"ANTHROPIC_API_KEY": "k", "AGENT_TASK": "task", "CONSTLE_A2A_URL": "u"}

	first := strings.Join(agentRunArgs("a", "n", "img", 0, []string{"sh"}, labels, env), " ")
	for i := 0; i < 50; i++ {
		if got := strings.Join(agentRunArgs("a", "n", "img", 0, []string{"sh"}, labels, env), " "); got != first {
			t.Fatalf("argv order is not deterministic:\n  %s\n  %s", first, got)
		}
	}
}

func argIndex(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

func hasOptionArg(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}
