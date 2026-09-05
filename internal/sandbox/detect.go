package sandbox

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/constle/constle/pkg/manifest"
)

// detectOut is where DetectBestBackend prints accepted-downgrade notices.
// It is a package variable so tests can capture the output.
var detectOut io.Writer = os.Stdout

// Selection is the outcome of backend selection: which backend will run, the
// isolation the Agentfile asked for, and the isolation that backend actually
// provides. Requested and Achieved are kept apart on purpose — the whole
// point of the isolation contract is that the two can never be conflated in
// runtime output or in audit evidence.
type Selection struct {
	Backend SandboxBackend
	Type    BackendType

	// Requested is the manifest's declared minimum isolation level.
	Requested manifest.IsolationLevel

	// Achieved is what Type actually delivers. It is never weaker than
	// Requested unless Downgraded is true.
	Achieved manifest.IsolationLevel

	// Downgraded reports that Achieved is weaker than Requested and that the
	// operator explicitly accepted that with --accept-isolation.
	Downgraded bool
}

// DetectBestBackend selects the sandbox backend for a run and enforces the
// isolation contract: a manifest's isolation level is a MINIMUM, not a
// preference. If the selected backend cannot provide it, the run is refused.
//
// override forces a specific backend ("docker" or "firecracker", normally
// from the --backend CLI flag) and errors out when that backend is unusable.
// --backend chooses an engine; it never relaxes the contract, so an explicit
// --backend=docker under `isolation: kernel` is refused exactly like the
// automatic path would be.
//
// accepted is the operator's explicit acknowledgement (from
// --accept-isolation=<level>) that a weaker boundary than the manifest
// declares is acceptable for this run. It is the ONLY way a run proceeds
// with Achieved weaker than Requested; when it is empty, an unsatisfiable
// contract is a hard error.
func DetectBestBackend(required manifest.IsolationLevel, override string, accepted manifest.IsolationLevel) (*Selection, error) {
	// Defense in depth. Validate() already rejects a malformed level, so this
	// is unreachable from `constle run` — but selection must not DEPEND on an
	// earlier caller having validated. An unrecognized level ranks as nothing,
	// which would make it satisfiable by the weakest backend present, and it
	// must not be routable through the downgrade path either: there is no
	// coherent "weaker than kernal" for an operator to accept. So it stops
	// here, before either decision.
	if !required.IsValid() {
		return nil, fmt.Errorf(
			"invalid isolation level %q in the manifest — valid levels: none, process, network, kernel",
			required,
		)
	}

	if accepted != "" && accepted.Satisfies(required) {
		return nil, fmt.Errorf(
			"--accept-isolation=%s is not a downgrade — the Agentfile already requires %q; drop the flag",
			accepted, required,
		)
	}

	switch override {
	case string(BackendDocker):
		if !dockerAvailable() {
			return nil, fmt.Errorf("backend %q requested but the Docker daemon is not reachable", override)
		}
		return applyIsolationContract(&DockerBackend{}, BackendDocker, required, accepted,
			"Docker was explicitly requested with --backend=docker")

	case string(BackendFirecracker):
		if reason := firecrackerUnavailableReason(); reason != "" {
			return nil, fmt.Errorf("backend %q requested but unavailable: %s", override, reason)
		}
		return applyIsolationContract(&FirecrackerBackend{}, BackendFirecracker, required, accepted, "")

	case "":
		// fall through to automatic selection
	default:
		return nil, fmt.Errorf("unknown backend %q — supported: docker, firecracker", override)
	}

	// Automatic selection. Firecracker is tried first whenever the contract
	// needs more than Docker can provide; only its absence is a reason to
	// look at a weaker backend, and that path is still held to the contract.
	var fcReason string
	if !BackendDocker.Provides().Satisfies(required) {
		if fcReason = firecrackerUnavailableReason(); fcReason == "" {
			return applyIsolationContract(&FirecrackerBackend{}, BackendFirecracker, required, accepted, "")
		}
	}

	if dockerAvailable() {
		why := "Docker is the only backend available on this host"
		if fcReason != "" {
			why = "Firecracker is unavailable: " + fcReason
		}
		return applyIsolationContract(&DockerBackend{}, BackendDocker, required, accepted, why)
	}

	msg := fmt.Sprintf("no sandbox backend available for isolation level %q\n", required)
	if fcReason != "" {
		msg += "  firecracker: " + fcReason + "\n"
	}
	msg += "  → please install Docker: https://docs.docker.com/get-docker/"

	return nil, fmt.Errorf("%s", msg)
}

// applyIsolationContract builds the Selection for a chosen backend and holds
// it to the isolation contract. why explains, in one line, how this backend
// came to be the candidate; it is shown to the operator on both the refusal
// and the accepted-downgrade path so neither is ever mysterious.
//
// This is the single choke point where a weaker-than-declared boundary can be
// let through, and it lets one through only on an explicit --accept-isolation.
func applyIsolationContract(b SandboxBackend, t BackendType, required, accepted manifest.IsolationLevel, why string) (*Selection, error) {
	provided := t.Provides()
	sel := &Selection{Backend: b, Type: t, Requested: required, Achieved: provided}

	if provided.Satisfies(required) {
		return sel, nil
	}

	if accepted == "" || !provided.Satisfies(accepted) {
		return nil, isolationContractError(required, t, provided, accepted, why)
	}

	sel.Downgraded = true
	noteAcceptedDowngrade(sel, why)
	return sel, nil
}

// isolationContractError is the actionable refusal an operator sees when the
// declared minimum cannot be built on this host. It names both levels, says
// why the stronger one is out of reach, and spells out the two ways forward.
func isolationContractError(required manifest.IsolationLevel, t BackendType, provided, accepted manifest.IsolationLevel, why string) error {
	msg := fmt.Sprintf(
		"isolation contract not satisfiable\n"+
			"  requested:  %-8s (declared in the Agentfile)\n"+
			"  achievable: %-8s (%s backend)\n"+
			"  %s\n",
		required, provided, t, why,
	)

	if accepted != "" {
		// The operator did acknowledge a downgrade, just not one this weak.
		msg += fmt.Sprintf(
			"  --accept-isolation=%s was given, but %s only provides %s\n",
			accepted, t, provided,
		)
	}

	if required == manifest.IsolationKernel {
		msg += "  → for real kernel isolation, set up Firecracker: scripts/setup-firecracker (needs KVM + root)\n"
	}
	msg += fmt.Sprintf(
		"  → or accept the weaker boundary for this run, explicitly:\n"+
			"      constle run --accept-isolation=%s <agentfile>",
		provided,
	)

	return fmt.Errorf("%s", msg)
}

// noteAcceptedDowngrade announces a downgrade the operator asked for. It is
// not a warning about a decision Constle made — it is the receipt for one the
// operator made, printed so the run's transcript records that this sandbox is
// weaker than the Agentfile declares.
// Write errors are discarded: detectOut is how this gets reported in the
// first place, so a failure to write it has nowhere left to go.
func noteAcceptedDowngrade(sel *Selection, why string) {
	_, _ = fmt.Fprintln(detectOut, "⚠️  ISOLATION DOWNGRADE ACCEPTED (--accept-isolation)")
	_, _ = fmt.Fprintf(detectOut, "   requested %s  ∙  achieved %s  (%s backend)\n", sel.Requested, sel.Achieved, sel.Type)
	_, _ = fmt.Fprintf(detectOut, "   %s\n", why)
	if sel.Type == BackendDocker {
		_, _ = fmt.Fprintln(detectOut, "   Docker provides network isolation only, NOT kernel-level isolation")
	}
}

// dockerAvailable reports whether the Docker daemon is reachable. It is a
// variable so tests can stub the daemon check without a real Docker install.
var dockerAvailable = func() bool {
	err := exec.Command("docker", "info").Run()
	return err == nil
}

// firecrackerUnavailableReason returns "" when the Firecracker backend is
// fully usable, or a human-readable reason why it is not. Checks are
// ordered from hard platform limits to fixable setup steps.
//
// It is a variable so tests can exercise the contract on hosts where the
// real answer would depend on the machine running them.
var firecrackerUnavailableReason = func() string {
	if runtime.GOOS != "linux" {
		return fmt.Sprintf("firecracker requires Linux (host is %s)", runtime.GOOS)
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return "/dev/kvm not found — KVM (hardware or nested virtualization) is required"
	}
	for _, binary := range []string{"firecracker", "jailer", "ip", "nft", "squid", "mkfs.ext4", "debugfs"} {
		if _, err := exec.LookPath(binary); err != nil {
			return fmt.Sprintf("%q not found in PATH — run scripts/setup-firecracker", binary)
		}
	}
	if _, err := os.Stat(fcKernelPath); err != nil {
		return fmt.Sprintf("guest kernel missing at %s — run scripts/setup-firecracker", fcKernelPath)
	}
	if _, err := os.Stat(filepath.Join(fcImagesDir, "default.ext4")); err != nil {
		return fmt.Sprintf("guest rootfs missing in %s — run scripts/setup-firecracker", fcImagesDir)
	}
	if os.Geteuid() != 0 {
		return "root privileges required (jailer, TAP and nftables setup) — re-run with sudo"
	}
	return ""
}
