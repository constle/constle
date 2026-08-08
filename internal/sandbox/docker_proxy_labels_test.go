package sandbox

import (
	"strings"
	"testing"
)

// TestProxyRunArgsCarrySweeperLabels pins the invariant cleanupAbandoned relies
// on: the Squid proxy must be labelled with constle.managed=true and its
// constle.run-id.
//
// This is not cosmetic. cleanupAbandoned finds abandoned resources purely by
// label, and the proxy is exactly the container left behind when a run dies
// between "proxy started" and "agent started" — a failing conformance test
// being the common way to hit that window. An unlabelled proxy is invisible to
// the sweeper permanently, so orphaned constle-proxy-* containers accumulate
// on the host with nothing that ever reaps them.
func TestProxyRunArgsCarrySweeperLabels(t *testing.T) {
	labels := map[string]string{
		"constle.managed":    "true",
		"constle.run-id":     "deadbeef",
		"constle.agent-name": "allowed-traffic-test",
	}
	args := proxyRunArgs("constle-proxy-deadbeef", "constle-ext-deadbeef", "/tmp/squid.conf", labels)

	for key, want := range labels {
		if !hasLabelArg(args, key+"="+want) {
			t.Errorf("proxy run args missing --label %s=%s\ngot: %v", key, want, args)
		}
	}

	// The image must stay last: everything after it is read by Docker as the
	// container's command, so a --label appended past this point would be
	// silently passed to Squid instead of registering as a label.
	if got := args[len(args)-1]; got != "ubuntu/squid:latest" {
		t.Errorf("last arg = %q, want the image to be last", got)
	}
}

// TestProxyRunArgsAreDeterministic guards the sort in proxyRunArgs. Without it
// Go's randomised map iteration makes the argv order vary run to run, which
// would leave the assertions above passing or failing at random.
func TestProxyRunArgsAreDeterministic(t *testing.T) {
	labels := map[string]string{"constle.managed": "true", "constle.run-id": "abc", "constle.agent-name": "x"}

	first := strings.Join(proxyRunArgs("p", "e", "/c", labels), " ")
	for i := 0; i < 50; i++ {
		if got := strings.Join(proxyRunArgs("p", "e", "/c", labels), " "); got != first {
			t.Fatalf("argv order is not deterministic:\n  %s\n  %s", first, got)
		}
	}
}

func hasLabelArg(args []string, want string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--label" && args[i+1] == want {
			return true
		}
	}
	return false
}
