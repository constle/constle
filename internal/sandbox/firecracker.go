package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/constle/constle/pkg/manifest"
)

// ============================================================
// firecracker.go — SandboxBackend implementation using Firecracker microVMs
//
// Per-run topology (all host-side, guest is untrusted):
//
//	[internet]
//	     |
//	host Squid (per run) ← listens ONLY on the TAP gateway IP:3128
//	     |
//	172.30.x.y/30        ← per-run /30 subnet, nftables allows ONLY
//	     |                  guest → gateway:3128, drops everything else
//	ct<runid> (TAP)      ← one TAP device per VM
//	     |
//	firecracker microVM  ← launched via jailer, driven over its API socket
//
// Enforcement lives entirely on the host (nftables + Squid ACLs): nothing
// the guest does to its own network stack can widen access. The guest's
// proxy environment variables point at the gateway IP literal, so the guest
// needs no DNS — and gets none.
//
// Host layout (populated by scripts/setup-firecracker):
//
//	/var/lib/constle/firecracker/vmlinux        pinned guest kernel
//	/var/lib/constle/firecracker/images/*.ext4  guest rootfs images
//	/var/lib/constle/jail/firecracker/<id>/     per-run jailer chroot
//	/var/lib/constle/runs/<id>/                 per-run state, squid config+log
// ============================================================

const (
	constleVarDir = "/var/lib/constle"
	fcKernelPath  = constleVarDir + "/firecracker/vmlinux"
	fcImagesDir   = constleVarDir + "/firecracker/images"
	fcRunsDir     = constleVarDir + "/runs"
	fcJailDir     = constleVarDir + "/jail"

	// fcUser is the unprivileged user jailer drops the VMM into.
	// Created by scripts/setup-firecracker.
	fcUser = "constle-fc"

	// fcSquidPort is the proxy port on the per-run TAP gateway address.
	fcSquidPort = 3128
)

// FirecrackerBackend implements SandboxBackend using Firecracker microVMs.
type FirecrackerBackend struct {
	// vmCmds holds the jailer/firecracker process handle per run so Wait can
	// reap the child. Runs started by other constle processes are handled
	// through PID polling instead (see Wait).
	vmCmds map[string]*exec.Cmd
}

// Start provisions the network, the per-run Squid proxy, and the microVM.
func (f *FirecrackerBackend) Start(m *manifest.AgentManifest) (*RunContext, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("the firecracker backend requires root (jailer, TAP and nftables setup) — re-run with sudo")
	}

	// Remove leftovers of runs that ended without a clean Stop() (host crash,
	// SIGKILL). Best-effort, same contract as the Docker backend.
	cleanupAbandonedFirecracker()

	runID, err := newRunID()
	if err != nil {
		return nil, fmt.Errorf("cannot generate run ID: %w", err)
	}

	rootfsPath, err := resolveRootfs(m.Sandbox.Image)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(fcKernelPath); err != nil {
		return nil, fmt.Errorf("guest kernel not found at %s — run scripts/setup-firecracker: %w", fcKernelPath, err)
	}

	runDir := filepath.Join(fcRunsDir, runID)
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create run directory: %w", err)
	}

	tapName := fcTAPName(runID)
	gatewayIP, guestIP, err := createTAP(runID, tapName)
	if err != nil {
		os.RemoveAll(runDir)
		return nil, fmt.Errorf("cannot create TAP device: %w", err)
	}

	if err := installNFTRules(runID, tapName, gatewayIP); err != nil {
		deleteTAP(tapName)
		os.RemoveAll(runDir)
		return nil, fmt.Errorf("cannot install nftables rules: %w", err)
	}

	squidPID, accessLogPath, err := startHostSquid(runID, runDir, gatewayIP, m.Sandbox.Network.AllowedHosts)
	if err != nil {
		deleteNFTRules(runID)
		deleteTAP(tapName)
		os.RemoveAll(runDir)
		return nil, fmt.Errorf("cannot start proxy: %w", err)
	}

	startTime := time.Now().UTC()

	cleanupNet := func() {
		killPID(squidPID)
		deleteNFTRules(runID)
		deleteTAP(tapName)
		os.RemoveAll(runDir)
	}

	workspacePath, err := buildWorkspaceImage(runDir, m, gatewayIP, guestIP)
	if err != nil {
		cleanupNet()
		return nil, fmt.Errorf("cannot build workspace image: %w", err)
	}

	chrootDir, err := prepareChroot(runID, rootfsPath, workspacePath)
	if err != nil {
		cleanupNet()
		return nil, fmt.Errorf("cannot prepare jailer chroot: %w", err)
	}

	vmCmd, err := launchVM(runID, runDir)
	if err != nil {
		os.RemoveAll(filepath.Dir(chrootDir))
		cleanupNet()
		return nil, fmt.Errorf("cannot launch microVM: %w", err)
	}

	if err := configureAndBootVM(runID, m.Sandbox.MemoryMB, tapName); err != nil {
		vmCmd.Process.Kill()
		vmCmd.Wait()
		os.RemoveAll(filepath.Dir(chrootDir))
		cleanupNet()
		return nil, fmt.Errorf("cannot boot microVM: %w", err)
	}

	state := &fcRunState{
		RunID:          runID,
		AgentName:      m.Identity.Name,
		VMPid:          vmCmd.Process.Pid,
		SquidPID:       squidPID,
		TAPDevice:      tapName,
		GatewayIP:      gatewayIP,
		StartedAt:      startTime,
		IsolationLevel: string(m.Sandbox.Isolation),
	}
	if err := writeFCState(state); err != nil {
		vmCmd.Process.Kill()
		vmCmd.Wait()
		os.RemoveAll(filepath.Dir(chrootDir))
		cleanupNet()
		return nil, fmt.Errorf("cannot write run state: %w", err)
	}

	if f.vmCmds == nil {
		f.vmCmds = map[string]*exec.Cmd{}
	}
	f.vmCmds[runID] = vmCmd

	return &RunContext{
		RunID:          runID,
		AgentName:      m.Identity.Name,
		Backend:        BackendFirecracker,
		StartTime:      startTime,
		IsolationLevel: string(m.Sandbox.Isolation),
		VMPid:          vmCmd.Process.Pid,
		TAPDevice:      tapName,
		SquidPID:       squidPID,
		SquidAccessLog: accessLogPath,
		RunDir:         runDir,
	}, nil
}

// Wait blocks until the firecracker process exits (the guest reboots when
// the agent finishes) and returns the agent's exit code, read back from the
// workspace image.
func (f *FirecrackerBackend) Wait(ctx *RunContext) (int, error) {
	if cmd, ok := f.vmCmds[ctx.RunID]; ok {
		// The error is deliberately ignored: a force-killed VM returns
		// "signal: killed" here, but the authoritative agent exit code
		// lives in the workspace image (or is absent, meaning killed).
		cmd.Wait()
	} else {
		for fcProcessAlive(ctx.VMPid, ctx.RunID) {
			time.Sleep(200 * time.Millisecond)
		}
	}

	out, err := exec.Command("debugfs", "-R", "cat /exitcode", fcWorkspacePath(ctx.RunID)).Output()
	if err != nil {
		return -1, fmt.Errorf("cannot read exit code from workspace: %w", err)
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		// No exitcode file: the VM was killed before the guest init could
		// write one. Report the conventional SIGKILL exit code, like a
		// force-stopped Docker container.
		return 137, nil
	}
	return code, nil
}

// Kill terminates the running agent: graceful first (Ctrl+Alt+Del through
// the API, which the guest init turns into an orderly shutdown), then
// SIGKILL after a 5-second grace period. Resources are left for Stop.
func (f *FirecrackerBackend) Kill(ctx *RunContext) error {
	if !fcProcessAlive(ctx.VMPid, ctx.RunID) {
		return nil
	}

	if err := sendCtrlAltDel(ctx.RunID); err == nil {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if !fcProcessAlive(ctx.VMPid, ctx.RunID) {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	return killPID(ctx.VMPid)
}

// Stop force-terminates the VM if still running and removes all host
// resources for this run: squid, TAP device, nftables table, chroot, state.
func (f *FirecrackerBackend) Stop(ctx *RunContext) error {
	errs := teardownFirecrackerRun(&fcRunState{
		RunID:     ctx.RunID,
		VMPid:     ctx.VMPid,
		SquidPID:  ctx.SquidPID,
		TAPDevice: ctx.TAPDevice,
	})

	// Reap the child if this process started it, so no zombie remains.
	if cmd, ok := f.vmCmds[ctx.RunID]; ok {
		cmd.Wait()
		delete(f.vmCmds, ctx.RunID)
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Logs returns the agent's combined stdout+stderr, read back from the
// workspace image (the guest init captures it to /workspace/agent.log).
func (f *FirecrackerBackend) Logs(ctx *RunContext) ([]byte, error) {
	out, err := exec.Command("debugfs", "-R", "cat /agent.log", fcWorkspacePath(ctx.RunID)).Output()
	if err != nil {
		return nil, fmt.Errorf("cannot read agent log from workspace: %w", err)
	}
	return out, nil
}

// resolveRootfs maps a manifest image reference to a guest rootfs image by
// convention: images/<sanitized-image>.ext4, falling back to default.ext4.
func resolveRootfs(image string) (string, error) {
	candidates := []string{}
	if image != "" {
		candidates = append(candidates, filepath.Join(fcImagesDir, sanitizeImageName(image)+".ext4"))
	}
	candidates = append(candidates, filepath.Join(fcImagesDir, "default.ext4"))

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no guest rootfs found for image %q (looked for %s) — run scripts/setup-firecracker",
		image, strings.Join(candidates, ", "))
}

// sanitizeImageName converts a Docker image reference to a filename-safe
// form: "basic-agent:latest" → "basic-agent-latest".
func sanitizeImageName(image string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, image)
}

// fcTAPName derives the host TAP interface name for a run.
// Interface names are limited to 15 chars: "ct" + 12 hex chars = 14.
func fcTAPName(runID string) string {
	id := runID
	if len(id) > 12 {
		id = id[:12]
	}
	return "ct" + id
}

// fcChrootDir returns the jailer chroot root for a run:
// <jail>/firecracker/<id>/root (jailer derives the middle segment from the
// exec-file name).
func fcChrootDir(runID string) string {
	return filepath.Join(fcJailDir, "firecracker", runID, "root")
}

// fcWorkspacePath returns the per-run workspace image path inside the chroot.
func fcWorkspacePath(runID string) string {
	return filepath.Join(fcChrootDir(runID), "workspace.ext4")
}

// buildWorkspaceImage creates the per-run ext4 drive carrying the run's
// environment and command into the guest. `mkfs.ext4 -d` packs a staging
// directory without requiring a loop mount.
func buildWorkspaceImage(runDir string, m *manifest.AgentManifest, gatewayIP, guestIP string) (string, error) {
	staging := filepath.Join(runDir, "ws")
	if err := os.MkdirAll(staging, 0700); err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)

	proxyURL := fmt.Sprintf("http://%s:%d", gatewayIP, fcSquidPort)
	env := map[string]string{
		"HTTP_PROXY":         proxyURL,
		"HTTPS_PROXY":        proxyURL,
		"http_proxy":         proxyURL,
		"https_proxy":        proxyURL,
		"CONSTLE_GUEST_CIDR": guestIP + "/30",
		"CONSTLE_GATEWAY_IP": gatewayIP,
	}
	for k, v := range forwardedHostEnv() {
		env[k] = v
	}

	var envFile strings.Builder
	for k, v := range env {
		fmt.Fprintf(&envFile, "export %s='%s'\n", k, strings.ReplaceAll(v, "'", `'\''`))
	}
	// 0600: the env file may carry API keys. The image itself stays inside
	// the root-owned chroot and is deleted by Stop.
	if err := os.WriteFile(filepath.Join(staging, "env"), []byte(envFile.String()), 0600); err != nil {
		return "", err
	}

	cmdScript := "#!/bin/sh\nexec sh /constle/default-cmd\n"
	if len(m.Sandbox.Command) > 0 {
		quoted := make([]string, len(m.Sandbox.Command))
		for i, arg := range m.Sandbox.Command {
			quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
		}
		cmdScript = "#!/bin/sh\nexec " + strings.Join(quoted, " ") + "\n"
	}
	if err := os.WriteFile(filepath.Join(staging, "cmd"), []byte(cmdScript), 0755); err != nil {
		return "", err
	}

	workspacePath := filepath.Join(runDir, "workspace.ext4")
	f, err := os.Create(workspacePath)
	if err != nil {
		return "", err
	}
	// 256 MB: room for the agent log alongside env+cmd.
	if err := f.Truncate(256 * 1024 * 1024); err != nil {
		f.Close()
		return "", err
	}
	f.Close()

	if out, err := exec.Command("mkfs.ext4", "-q", "-F", "-d", staging, workspacePath).CombinedOutput(); err != nil {
		return "", fmt.Errorf("mkfs.ext4: %s", strings.TrimSpace(string(out)))
	}
	return workspacePath, nil
}

// prepareChroot lays out the jailer chroot with the kernel (hard-linked),
// a private copy of the rootfs, and the workspace image, owned by the
// unprivileged VMM user.
func prepareChroot(runID, rootfsPath, workspacePath string) (string, error) {
	chroot := fcChrootDir(runID)
	if err := os.MkdirAll(chroot, 0750); err != nil {
		return "", err
	}

	kernelTarget, err := filepath.EvalSymlinks(fcKernelPath)
	if err != nil {
		return "", fmt.Errorf("cannot resolve kernel path: %w", err)
	}
	if err := os.Link(kernelTarget, filepath.Join(chroot, "vmlinux")); err != nil {
		return "", fmt.Errorf("cannot link kernel into chroot: %w", err)
	}

	// The guest writes to its root filesystem (/tmp, Python runtime files),
	// so each VM gets a private sparse copy of the shared image.
	if out, err := exec.Command("cp", "--sparse=always",
		rootfsPath, filepath.Join(chroot, "rootfs.ext4")).CombinedOutput(); err != nil {
		return "", fmt.Errorf("cannot copy rootfs: %s", strings.TrimSpace(string(out)))
	}

	if err := os.Rename(workspacePath, filepath.Join(chroot, "workspace.ext4")); err != nil {
		return "", fmt.Errorf("cannot move workspace into chroot: %w", err)
	}

	uid, gid, err := lookupFCUser()
	if err != nil {
		return "", err
	}
	for _, name := range []string{"", "vmlinux", "rootfs.ext4", "workspace.ext4"} {
		if err := os.Chown(filepath.Join(chroot, name), uid, gid); err != nil {
			return "", fmt.Errorf("cannot chown chroot files: %w", err)
		}
	}
	return chroot, nil
}

// lookupFCUser resolves the unprivileged VMM user created by setup.
func lookupFCUser() (uid, gid int, err error) {
	uid, gid, err = lookupUserIDs(fcUser)
	if err != nil {
		return 0, 0, fmt.Errorf("user %q not found — run scripts/setup-firecracker: %w", fcUser, err)
	}
	return uid, gid, nil
}

// lookupUserIDs resolves a username to numeric uid/gid.
func lookupUserIDs(name string) (uid, gid int, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, _ = strconv.Atoi(u.Uid)
	gid, _ = strconv.Atoi(u.Gid)
	return uid, gid, nil
}

// killPID sends SIGKILL, ignoring already-gone processes.
func killPID(pid int) error {
	if pid <= 0 {
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	if err := proc.Kill(); err != nil && !strings.Contains(err.Error(), "already finished") {
		return err
	}
	return nil
}
