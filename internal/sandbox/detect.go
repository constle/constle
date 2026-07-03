package sandbox

import (
	"fmt"
	"os/exec"

	"github.com/constle/constle/pkg/manifest"
)

// DetectBestBackend selects the best available sandbox backend for the required
// isolation level.
func DetectBestBackend(required manifest.IsolationLevel) (SandboxBackend, BackendType, error) {
	if dockerAvailable() {
		if required == manifest.IsolationKernel {
			// Docker provides network isolation but not true kernel-level isolation.
			// Acceptable for development; use Firecracker for production.
			fmt.Println("⚠️  warning: kernel isolation requested but only Docker is available")
			fmt.Println("   Docker provides network isolation but NOT kernel-level isolation")
			fmt.Println("   For production use, install Constle with Firecracker support")
		}
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
