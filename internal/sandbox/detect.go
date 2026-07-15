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

// detectOut is where DetectBestBackend prints isolation-downgrade warnings.
// It is a package variable so tests can capture the output.
var detectOut io.Writer = os.Stdout

// DetectBestBackend selects the best available sandbox backend for the
// required isolation level.
//
// override forces a specific backend ("docker" or "firecracker", normally
// from the --backend CLI flag) and errors out when that backend is
// unusable — an explicit request never falls back silently. When override
// is empty, `isolation: kernel` selects Firecracker if the host supports
// it and falls back to Docker with a clear message otherwise.
func DetectBestBackend(required manifest.IsolationLevel, override string) (SandboxBackend, BackendType, error) {
	switch override {
	case string(BackendDocker):
		if !dockerAvailable() {
			return nil, "", fmt.Errorf("backend %q requested but the Docker daemon is not reachable", override)
		}
		// An explicit --backend=docker override still downgrades isolation
		// when the manifest asks for kernel-level isolation. Warn just as
		// loudly as the automatic path does, instead of running silently.
		if required == manifest.IsolationKernel {
			warnKernelIsolationOnDocker("Docker was explicitly requested with --backend=docker")
		}
		return &DockerBackend{}, BackendDocker, nil

	case string(BackendFirecracker):
		if reason := firecrackerUnavailableReason(); reason != "" {
			return nil, "", fmt.Errorf("backend %q requested but unavailable: %s", override, reason)
		}
		return &FirecrackerBackend{}, BackendFirecracker, nil

	case "":
		// fall through to automatic selection
	default:
		return nil, "", fmt.Errorf("unknown backend %q — supported: docker, firecracker", override)
	}

	if required == manifest.IsolationKernel {
		if reason := firecrackerUnavailableReason(); reason == "" {
			return &FirecrackerBackend{}, BackendFirecracker, nil
		} else if dockerAvailable() {
			warnKernelIsolationOnDocker("Firecracker is unavailable: " + reason)
			return &DockerBackend{}, BackendDocker, nil
		}
	}

	if dockerAvailable() {
		return &DockerBackend{}, BackendDocker, nil
	}

	return nil, "", fmt.Errorf(
		"no sandbox backend available for isolation level %q\n"+
			"  → please install Docker: https://docs.docker.com/get-docker/",
		required,
	)
}

// warnKernelIsolationOnDocker prints a warning that a manifest requiring
// kernel-level isolation is being served by the Docker backend, which
// isolates the network but NOT the kernel. reason explains why Docker is
// being used (Firecracker unavailable, or an explicit --backend=docker
// override). Both the automatic and the override paths route through here so
// the downgrade is never silent.
func warnKernelIsolationOnDocker(reason string) {
	fmt.Fprintln(detectOut, "⚠️  warning: kernel isolation requested but running on Docker:")
	fmt.Fprintln(detectOut, "   "+reason)
	fmt.Fprintln(detectOut, "   Docker provides network isolation only, NOT kernel-level isolation")
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
func firecrackerUnavailableReason() string {
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
