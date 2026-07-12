package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/constle/constle/pkg/manifest"
)

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
			fmt.Println("⚠️  warning: kernel isolation requested but Firecracker is unavailable:")
			fmt.Println("   " + reason)
			fmt.Println("   falling back to Docker — network isolation only, NOT kernel-level isolation")
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

// dockerAvailable reports whether the Docker daemon is reachable.
func dockerAvailable() bool {
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
