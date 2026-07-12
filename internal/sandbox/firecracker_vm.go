package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================
// firecracker_vm.go — launching and driving the microVM
//
// The VMM is started through jailer, which chroots into
// /var/lib/constle/jail/firecracker/<id>/root and drops to the
// unprivileged constle-fc user before exec()ing firecracker (same PID).
// The VM is then configured over Firecracker's HTTP API on the Unix
// domain socket jailer exposes inside the chroot.
// ============================================================

// fcBootArgs is the guest kernel command line. init=/constle/init selects
// the Constle guest init baked into the rootfs by scripts/setup-firecracker.
const fcBootArgs = "console=ttyS0 reboot=k panic=1 pci=off init=/constle/init"

// fcSocketPath returns the API socket path for a run (firecracker's default
// /run/firecracker.socket, seen from outside the chroot).
func fcSocketPath(runID string) string {
	return filepath.Join(fcChrootDir(runID), "run", "firecracker.socket")
}

// fcConsoleLogPath returns the serial console capture file for a run.
func fcConsoleLogPath(runDir string) string {
	return filepath.Join(runDir, "console.log")
}

// launchVM starts jailer (which execs into firecracker — the returned
// command's PID is the VMM PID) and waits for the API socket to appear.
// The serial console and VMM log stream into <runDir>/console.log.
func launchVM(runID, runDir string) (*exec.Cmd, error) {
	uid, gid, err := lookupFCUser()
	if err != nil {
		return nil, err
	}

	console, err := os.OpenFile(fcConsoleLogPath(runDir), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	defer console.Close()

	cmd := exec.Command("jailer",
		"--id", runID,
		"--exec-file", "/usr/local/bin/firecracker",
		"--uid", fmt.Sprint(uid),
		"--gid", fmt.Sprint(gid),
		"--chroot-base-dir", fcJailDir,
		"--cgroup-version", "2",
	)
	cmd.Stdout = console
	cmd.Stderr = console

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("jailer: %w", err)
	}

	socket := fcSocketPath(runID)
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(socket); err == nil {
			return cmd, nil
		}
		// If the VMM died during startup, surface its console output.
		if cmd.ProcessState != nil || !processExists(cmd.Process.Pid) {
			cmd.Wait()
			tail, _ := os.ReadFile(fcConsoleLogPath(runDir))
			return nil, fmt.Errorf("firecracker exited during startup: %s", lastLines(tail, 5))
		}
		time.Sleep(100 * time.Millisecond)
	}
	cmd.Process.Kill()
	cmd.Wait()
	return nil, fmt.Errorf("firecracker API socket did not appear at %s", socket)
}

// configureAndBootVM drives the Firecracker API: machine config, kernel,
// drives, network interface, then InstanceStart. All guest paths are
// relative to the jailer chroot.
func configureAndBootVM(runID string, memoryMB int, tapName string) error {
	if memoryMB == 0 {
		memoryMB = 512
	}

	api := newFCClient(fcSocketPath(runID))

	steps := []struct {
		path string
		body map[string]any
	}{
		{"/machine-config", map[string]any{
			"vcpu_count":   1,
			"mem_size_mib": memoryMB,
			"smt":          false,
		}},
		{"/boot-source", map[string]any{
			"kernel_image_path": "/vmlinux",
			"boot_args":         fcBootArgs,
		}},
		{"/drives/rootfs", map[string]any{
			"drive_id":       "rootfs",
			"path_on_host":   "/rootfs.ext4",
			"is_root_device": true,
			"is_read_only":   false,
		}},
		{"/drives/workspace", map[string]any{
			"drive_id":       "workspace",
			"path_on_host":   "/workspace.ext4",
			"is_root_device": false,
			"is_read_only":   false,
		}},
		{"/network-interfaces/eth0", map[string]any{
			"iface_id":      "eth0",
			"guest_mac":     fcGuestMAC(runID),
			"host_dev_name": tapName,
		}},
		{"/actions", map[string]any{
			"action_type": "InstanceStart",
		}},
	}

	for _, step := range steps {
		if err := api.put(step.path, step.body); err != nil {
			return fmt.Errorf("PUT %s: %w", step.path, err)
		}
	}
	return nil
}

// sendCtrlAltDel asks the guest to shut down gracefully; the guest init
// traps the resulting SIGINT and exits through its normal reboot path.
func sendCtrlAltDel(runID string) error {
	return newFCClient(fcSocketPath(runID)).put("/actions", map[string]any{
		"action_type": "SendCtrlAltDel",
	})
}

// fcGuestMAC derives a stable locally-administered MAC from the run ID.
func fcGuestMAC(runID string) string {
	id := runID + "00000000"
	return fmt.Sprintf("06:00:%s:%s:%s:%s", id[0:2], id[2:4], id[4:6], id[6:8])
}

// fcClient is a minimal Firecracker API client over a Unix domain socket.
type fcClient struct {
	http *http.Client
}

func newFCClient(socketPath string) *fcClient {
	return &fcClient{http: &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}}
}

// put sends a PUT request and treats any non-2xx response as an error,
// including Firecracker's fault message in the error text.
func (c *fcClient) put(path string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, "http://localhost"+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("firecracker API %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

// processExists reports whether a PID is present (any state).
func processExists(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// lastLines returns up to n trailing non-empty lines of b, joined by " | ".
func lastLines(b []byte, n int) string {
	lines := []string{}
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			lines = append(lines, string(bytes.TrimSpace(line)))
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 0 {
		return "(no console output)"
	}
	return strings.Join(lines, " | ")
}
