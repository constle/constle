package sandbox

import (
	"bytes"
	"strings"
	"testing"

	"github.com/constle/constle/pkg/manifest"
)

// fcAvailable is the sentinel firecrackerUnavailableReason returns when the
// Firecracker backend is usable.
const fcAvailable = ""

// fcMissing is a stand-in for any real "Firecracker is not usable here"
// reason. The contract must not depend on which one it is.
const fcMissing = "/dev/kvm not found — KVM (hardware or nested virtualization) is required"

// stubHost fixes what this host appears to offer for the duration of one
// test and captures detectOut, restoring all three afterwards. fcReason is
// "" when Firecracker is available.
func stubHost(t *testing.T, docker bool, fcReason string) *bytes.Buffer {
	t.Helper()

	origDocker, origFC, origOut := dockerAvailable, firecrackerUnavailableReason, detectOut
	t.Cleanup(func() {
		dockerAvailable, firecrackerUnavailableReason, detectOut = origDocker, origFC, origOut
	})

	dockerAvailable = func() bool { return docker }
	firecrackerUnavailableReason = func() string { return fcReason }
	buf := &bytes.Buffer{}
	detectOut = buf
	return buf
}

// ------------------------------------------------------------
// The contract: a declared minimum is a minimum, not a preference
// ------------------------------------------------------------

// TestKernelIsolationNeverFallsBackToDockerAutomatically is the regression
// guard for the behavior this contract replaced: automatic detection used to
// warn and then run `isolation: kernel` on Docker when Firecracker was
// unavailable. Docker shares the host kernel, so that made a declared
// protection look satisfied while the actual boundary was weaker. It must
// now refuse to run.
func TestKernelIsolationNeverFallsBackToDockerAutomatically(t *testing.T) {
	buf := stubHost(t, true, fcMissing)

	sel, err := DetectBestBackend(manifest.IsolationKernel, "", "")
	if err == nil {
		t.Fatalf("DetectBestBackend() returned %+v with nil error — kernel isolation must never "+
			"silently fall back to Docker", sel)
	}
	if sel != nil {
		t.Errorf("selection = %+v, want nil on a refused run", sel)
	}

	msg := err.Error()
	for _, want := range []string{
		"isolation contract not satisfiable",
		"kernel",                     // what was requested
		"network",                    // what is actually achievable
		fcMissing,                    // why the stronger boundary is out of reach
		"--accept-isolation=network", // the one way forward that is explicit
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should mention %q, got:\n%s", want, msg)
		}
	}
	if out := buf.String(); out != "" {
		t.Errorf("a refused run must not print a downgrade notice, got:\n%s", out)
	}
}

// TestExplicitDockerOverrideCannotSatisfyKernel covers the second way the old
// behavior leaked: --backend=docker selects an engine, and an engine choice
// must not double as permission to weaken the declared boundary. Before the
// contract this warned and ran; it must now be refused just like the
// automatic path.
func TestExplicitDockerOverrideCannotSatisfyKernel(t *testing.T) {
	buf := stubHost(t, true, fcAvailable)

	sel, err := DetectBestBackend(manifest.IsolationKernel, string(BackendDocker), "")
	if err == nil {
		t.Fatalf("DetectBestBackend() returned %+v with nil error — --backend=docker must not "+
			"satisfy kernel isolation on its own", sel)
	}
	if !strings.Contains(err.Error(), "isolation contract not satisfiable") {
		t.Errorf("want an isolation-contract refusal, got:\n%s", err)
	}
	if out := buf.String(); out != "" {
		t.Errorf("a refused run must not print a downgrade notice, got:\n%s", out)
	}
}

// TestKernelIsolationUsesFirecrackerWhenAvailable is the happy path the
// contract exists to protect: when the host can actually provide the declared
// boundary, it is provided, silently and without ceremony.
func TestKernelIsolationUsesFirecrackerWhenAvailable(t *testing.T) {
	buf := stubHost(t, true, fcAvailable)

	sel, err := DetectBestBackend(manifest.IsolationKernel, "", "")
	if err != nil {
		t.Fatalf("DetectBestBackend() error = %v, want nil", err)
	}
	if sel.Type != BackendFirecracker {
		t.Errorf("backend type = %q, want %q", sel.Type, BackendFirecracker)
	}
	if _, ok := sel.Backend.(*FirecrackerBackend); !ok {
		t.Errorf("backend = %T, want *FirecrackerBackend", sel.Backend)
	}
	if sel.Achieved != manifest.IsolationKernel {
		t.Errorf("achieved = %q, want %q", sel.Achieved, manifest.IsolationKernel)
	}
	if sel.Downgraded {
		t.Error("Downgraded = true on a fully satisfied contract")
	}
	if out := buf.String(); out != "" {
		t.Errorf("a satisfied contract must print nothing, got:\n%s", out)
	}
}

// ------------------------------------------------------------
// The one accepted downgrade path: explicit operator intent
// ------------------------------------------------------------

// TestAcceptIsolationAllowsDowngradeAutomatically shows the new behavior: the
// same host that now refuses the run proceeds once the operator names the
// weaker boundary they are willing to accept — and the run is labelled with
// both levels, not just the achieved one.
func TestAcceptIsolationAllowsDowngradeAutomatically(t *testing.T) {
	buf := stubHost(t, true, fcMissing)

	sel, err := DetectBestBackend(manifest.IsolationKernel, "", manifest.IsolationNetwork)
	if err != nil {
		t.Fatalf("DetectBestBackend() error = %v, want nil with an explicit downgrade", err)
	}
	if sel.Type != BackendDocker {
		t.Errorf("backend type = %q, want %q", sel.Type, BackendDocker)
	}
	if sel.Requested != manifest.IsolationKernel {
		t.Errorf("requested = %q, want %q", sel.Requested, manifest.IsolationKernel)
	}
	if sel.Achieved != manifest.IsolationNetwork {
		t.Errorf("achieved = %q, want %q", sel.Achieved, manifest.IsolationNetwork)
	}
	if !sel.Downgraded {
		t.Error("Downgraded = false, want true on an accepted downgrade")
	}

	out := buf.String()
	for _, want := range []string{
		"ISOLATION DOWNGRADE ACCEPTED",
		"requested kernel",
		"achieved network",
		"NOT kernel-level isolation",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("downgrade notice should mention %q, got:\n%s", want, out)
		}
	}
}

// TestAcceptIsolationAllowsExplicitDockerOverride pairs --backend=docker with
// the acknowledgement, which is the combination an operator who genuinely
// wants Docker under a kernel manifest has to type.
func TestAcceptIsolationAllowsExplicitDockerOverride(t *testing.T) {
	buf := stubHost(t, true, fcAvailable)

	sel, err := DetectBestBackend(manifest.IsolationKernel, string(BackendDocker), manifest.IsolationNetwork)
	if err != nil {
		t.Fatalf("DetectBestBackend() error = %v, want nil", err)
	}
	if sel.Type != BackendDocker || !sel.Downgraded {
		t.Errorf("selection = %+v, want the Docker backend flagged as downgraded", sel)
	}
	if !strings.Contains(buf.String(), "--backend=docker") {
		t.Errorf("notice should say Docker was explicitly requested, got:\n%s", buf.String())
	}
}

// TestAcceptIsolationTooWeakForTheBackendStillRefuses guards the acceptance
// itself: the flag is a specific level, not a blanket waiver. A backend that
// cannot even reach the accepted level is still refused.
func TestAcceptIsolationTooWeakForTheBackendStillRefuses(t *testing.T) {
	// wasm is declared but unimplemented, so it provides nothing. Selecting it
	// directly is not reachable from the CLI; going through the contract check
	// is what proves an unimplemented backend can never pass it.
	sel, err := applyIsolationContract(nil, BackendWasm, manifest.IsolationKernel, manifest.IsolationNetwork, "hypothetical")
	if err == nil {
		t.Fatalf("applyIsolationContract() returned %+v with nil error — a backend that provides %q "+
			"must not satisfy --accept-isolation=network", sel, BackendWasm.Provides())
	}
	if !strings.Contains(err.Error(), "--accept-isolation=network was given") {
		t.Errorf("error should explain that the acknowledgement was not enough, got:\n%s", err)
	}
}

// TestAcceptIsolationRejectsNonDowngrade keeps the flag meaningful: asking to
// "accept" a level the Agentfile already requires is not a downgrade, and
// silently ignoring it would leave an operator believing they had waived
// something they had not.
func TestAcceptIsolationRejectsNonDowngrade(t *testing.T) {
	stubHost(t, true, fcAvailable)

	for _, accepted := range []manifest.IsolationLevel{manifest.IsolationNetwork, manifest.IsolationKernel} {
		if _, err := DetectBestBackend(manifest.IsolationNetwork, "", accepted); err == nil {
			t.Errorf("--accept-isolation=%s against a %q manifest: error = nil, want a rejection",
				accepted, manifest.IsolationNetwork)
		}
	}
}

// ------------------------------------------------------------
// Preserved behavior
// ------------------------------------------------------------

// TestWeakerIsolationLevelsRunOnDockerUnchanged confirms the contract is
// scoped to boundaries Docker cannot provide: levels it does satisfy keep
// selecting it, quietly, with no downgrade flag set.
func TestWeakerIsolationLevelsRunOnDockerUnchanged(t *testing.T) {
	for _, level := range []manifest.IsolationLevel{
		manifest.IsolationNone,
		manifest.IsolationProcess,
		manifest.IsolationNetwork,
	} {
		for _, override := range []string{"", string(BackendDocker)} {
			buf := stubHost(t, true, fcMissing)

			sel, err := DetectBestBackend(level, override, "")
			if err != nil {
				t.Fatalf("DetectBestBackend(%q, %q) error = %v, want nil", level, override, err)
			}
			if sel.Type != BackendDocker {
				t.Errorf("isolation %q: backend type = %q, want %q", level, sel.Type, BackendDocker)
			}
			if sel.Achieved != manifest.IsolationNetwork {
				t.Errorf("isolation %q: achieved = %q, want %q", level, sel.Achieved, manifest.IsolationNetwork)
			}
			if sel.Downgraded {
				t.Errorf("isolation %q: Downgraded = true, but Docker satisfies this level", level)
			}
			if out := buf.String(); out != "" {
				t.Errorf("isolation %q should print nothing, got:\n%s", level, out)
			}
		}
	}
}

// TestExplicitDockerOverrideErrorsWhenDaemonDown confirms the override still
// fails hard (never warns-then-continues) when Docker itself is unreachable.
func TestExplicitDockerOverrideErrorsWhenDaemonDown(t *testing.T) {
	buf := stubHost(t, false, fcAvailable)

	if _, err := DetectBestBackend(manifest.IsolationKernel, string(BackendDocker), ""); err == nil {
		t.Fatal("DetectBestBackend() error = nil, want an error when the Docker daemon is down")
	}
	if out := buf.String(); out != "" {
		t.Errorf("no notice should be printed when Docker is unavailable, got:\n%s", out)
	}
}

// TestExplicitFirecrackerOverrideErrorsWhenUnavailable confirms an explicit
// Firecracker request never degrades into something else.
func TestExplicitFirecrackerOverrideErrorsWhenUnavailable(t *testing.T) {
	stubHost(t, true, fcMissing)

	_, err := DetectBestBackend(manifest.IsolationKernel, string(BackendFirecracker), manifest.IsolationNetwork)
	if err == nil {
		t.Fatal("DetectBestBackend() error = nil, want an error when Firecracker is unavailable")
	}
	if !strings.Contains(err.Error(), fcMissing) {
		t.Errorf("error should carry the unavailability reason, got:\n%s", err)
	}
}

// TestNoBackendAvailableReportsBothReasons keeps the "nothing works here"
// error useful: it names the Firecracker obstacle it already discovered
// instead of only pointing at Docker.
func TestNoBackendAvailableReportsBothReasons(t *testing.T) {
	stubHost(t, false, fcMissing)

	_, err := DetectBestBackend(manifest.IsolationKernel, "", "")
	if err == nil {
		t.Fatal("DetectBestBackend() error = nil, want an error when no backend is available")
	}
	for _, want := range []string{"no sandbox backend available", fcMissing, "get-docker"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got:\n%s", want, err)
		}
	}
}

// TestUnknownBackendOverrideRejected keeps a typo from being read as "no
// override" and quietly selecting something.
func TestUnknownBackendOverrideRejected(t *testing.T) {
	stubHost(t, true, fcAvailable)

	if _, err := DetectBestBackend(manifest.IsolationNetwork, "podman", ""); err == nil {
		t.Fatal("DetectBestBackend() error = nil, want an error for an unknown backend")
	}
}

// TestBackendProvides pins the achieved-isolation table every contract
// decision is derived from.
func TestBackendProvides(t *testing.T) {
	cases := map[BackendType]manifest.IsolationLevel{
		BackendFirecracker:  manifest.IsolationKernel,
		BackendDocker:       manifest.IsolationNetwork,
		BackendWasm:         manifest.IsolationNone,
		BackendType("nope"): manifest.IsolationNone,
	}
	for backend, want := range cases {
		if got := backend.Provides(); got != want {
			t.Errorf("%q.Provides() = %q, want %q", backend, got, want)
		}
	}
}
