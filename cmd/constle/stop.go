package main

// ============================================================
// stop.go — constle stop <run_id>
//
// Finds and destroys all Docker resources belonging to a run:
//   constle-agent-{id}  constle-proxy-{id}  (containers)
//   constle-int-{id}    constle-ext-{id}    (networks)
//
// Resource names are derived from the run_id by convention — the same
// convention used in docker.go — so no Docker API query is needed.
//
// The command is idempotent: "No such container/network" errors are
// silently ignored, so calling it on a partially-cleaned run is safe.
// ============================================================

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/constle/constle/internal/sandbox"
)

func cmdStop(runID string) error {
	printf("\nconstle stop %s\n\n", runID)

	// Firecracker-backed runs are recognized by their state directory and
	// torn down through the sandbox package (VMM process, TAP device,
	// nftables table, chroot). Everything else falls through to Docker.
	if sandbox.FirecrackerRunExists(runID) {
		printStep("removing firecracker microVM, TAP device and firewall rules...")
		if err := sandbox.StopFirecrackerRun(runID); err != nil {
			return err
		}
		printOK("run %s stopped and resources removed", runID)
		printf("\n")
		return nil
	}

	containers := []string{
		"constle-agent-" + runID,
		"constle-proxy-" + runID,
	}
	networks := []string{
		"constle-int-" + runID,
		"constle-ext-" + runID,
	}

	var errs []string

	// docker rm -f stops a running container and removes it in one call.
	// For a container that is already stopped (exited/dead), it just removes.
	printStep("removing containers...")
	for _, name := range containers {
		out, err := exec.Command("docker", "rm", "-f", name).CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if !strings.Contains(msg, "No such container") {
				errs = append(errs, fmt.Sprintf("%s: %s", name, msg))
			}
		}
	}

	printStep("removing networks...")
	for _, net := range networks {
		out, err := exec.Command("docker", "network", "rm", net).CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if !strings.Contains(msg, "No such network") {
				errs = append(errs, fmt.Sprintf("%s: %s", net, msg))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("stop errors: %s", strings.Join(errs, "; "))
	}

	printOK("run %s stopped and resources removed", runID)
	printf("\n")
	return nil
}
