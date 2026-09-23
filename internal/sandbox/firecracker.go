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

	"github.com/constle/constle/internal/agentenv"
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

	// fcUser is the unprivileged user jailer drops the VMM into.
	// Created by scripts/setup-firecracker.
	fcUser = "constle-fc"

	// fcSquidPort is the proxy port on the per-run TAP gateway address.
	fcSquidPort = 3128
)

// fcRunsDir holds the per-run state directories and fcJailDir the jailer
// chroot base. They are variables only so tests can point them at a
// temporary tree; nothing outside tests assigns them.
var (
	fcRunsDir = constleVarDir + "/runs"
	fcJailDir = constleVarDir + "/jail"
)

// FirecrackerBackend implements SandboxBackend using Firecracker microVMs.
type FirecrackerBackend struct {
	// vmCmds holds the jailer/firecracker process handle per run so Wait can
	// reap the child. Runs started by other constle processes are handled
	// through PID polling instead (see Wait).
	vmCmds map[string]*exec.Cmd

	// mcpGate is attached by the CLI (SetMCPGate) when the manifest declares
	// MCP servers; Start fails closed if servers are declared without it.
	mcpGate MCPGateBinder

	// a2aGate is attached by the CLI (SetA2AGate) when the manifest declares
	// a2a peers; Start fails closed if peers are declared without it.
	a2aGate A2AGateBinder
}

// Start provisions the network, the per-run Squid proxy, and the microVM.
func (f *FirecrackerBackend) Start(m *manifest.AgentManifest) (*RunContext, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("the firecracker backend requires root (jailer, TAP and nftables setup) — re-run with sudo")
	}

	if len(m.MCP.Servers) > 0 && f.mcpGate == nil {
		// Fail closed: declared MCP servers without a gate would either not
		// work or, worse, tempt a fallback to direct access.
		return nil, fmt.Errorf("manifest declares mcp servers but no MCP gate is attached to the backend")
	}
	if len(m.A2A.Peers) > 0 && f.a2aGate == nil {
		// Same fail-closed rule for A2A: declared peers without the signing
		// gate must never fall back to unsigned direct access.
		return nil, fmt.Errorf("manifest declares a2a peers but no A2A gate is attached to the backend")
	}

	// Resolve the declared credentials before the first resource is created,
	// for the same reason DockerBackend.Start does. Host state here is heavier
	// — a TAP device, nftables rules, a Squid process, the jailer chroot — so a
	// late refusal would have more to unwind, not less.
	credEnv, err := agentenv.Resolve(m)
	if err != nil {
		return nil, err
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

	// 0755 on purpose: `constle ps` reads the state file here without root
	// (fcRunState.write, firecracker_state.go). The directory mode is not a
	// confidentiality boundary for anything inside it — every file written
	// into this tree carries its own mode.
	runDir := filepath.Join(fcRunsDir, runID)
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create run directory: %w", err)
	}

	// As in DockerBackend.Start, every rollback step from here on discards
	// its error deliberately: the returned error explains the failure, one
	// failing step must not mask it or stop the steps after it, and the
	// leftovers are swept up by cleanupAbandonedFirecracker(). Host state
	// here is heavier than Docker's (TAP device, nftables rules, a Squid
	// process, the jailer chroot), which is why the steps accumulate.
	tapName := fcTAPName(runID)
	gatewayIP, guestIP, err := createTAP(runID, tapName)
	if err != nil {
		_ = os.RemoveAll(runDir)
		return nil, fmt.Errorf("cannot create TAP device: %w", err)
	}

	// Bind the gates on the TAP gateway address before installing the
	// nftables rules, which open exactly guest → gateway on these ports
	// (alongside the Squid port). Unlike the Docker backend, the guest
	// reaches the gates directly — constle owns this network namespace.
	gatePort := 0
	gateToken := ""
	a2aPort := 0
	a2aToken := ""
	if len(m.MCP.Servers) > 0 {
		gatePort, gateToken, err = f.mcpGate.Bind(runID, []string{gatewayIP})
		if err != nil {
			_ = deleteTAP(tapName)
			_ = os.RemoveAll(runDir)
			return nil, fmt.Errorf("cannot bind MCP gate: %w", err)
		}
	}
	if len(m.A2A.Peers) > 0 {
		a2aPort, a2aToken, err = f.a2aGate.Bind(runID, []string{gatewayIP})
		if err != nil {
			_ = deleteTAP(tapName)
			_ = os.RemoveAll(runDir)
			return nil, fmt.Errorf("cannot bind A2A gate: %w", err)
		}
	}
	runGatePorts := gatePorts(gatePort, a2aPort)

	if err := installNFTRules(runID, tapName, gatewayIP, runGatePorts); err != nil {
		_ = deleteTAP(tapName)
		_ = os.RemoveAll(runDir)
		return nil, fmt.Errorf("cannot install nftables rules: %w", err)
	}

	squidPID, accessLogPath, err := startHostSquid(runID, runDir, gatewayIP, m.Sandbox.Network.AllowedHosts, runGatePorts)
	if err != nil {
		_ = deleteNFTRules(runID)
		_ = deleteTAP(tapName)
		_ = os.RemoveAll(runDir)
		return nil, fmt.Errorf("cannot start proxy: %w", err)
	}

	startTime := time.Now().UTC()

	cleanupNet := func() {
		_ = killPID(squidPID)
		_ = deleteNFTRules(runID)
		_ = deleteTAP(tapName)
		_ = os.RemoveAll(runDir)
	}

	gateEnv := mcpGateEnv(m, gatewayIP, gatePort, gateToken)
	for k, v := range a2aGateEnv(gatewayIP, a2aPort, a2aToken) {
		gateEnv[k] = v
	}
	if len(runGatePorts) > 0 {
		// The guest reaches the gates directly on the TAP gateway; keep
		// clients that honour proxy env vars from detouring through Squid.
		// (Squid also carries a gate allow rule for clients that don't.)
		gateEnv["NO_PROXY"] = gatewayIP
		gateEnv["no_proxy"] = gatewayIP
	}

	workspacePath, err := buildWorkspaceImage(runDir, m, gatewayIP, guestIP, credEnv, gateEnv)
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
		_ = os.RemoveAll(filepath.Dir(chrootDir))
		cleanupNet()
		return nil, fmt.Errorf("cannot launch microVM: %w", err)
	}

	if err := configureAndBootVM(runID, m.Sandbox.MemoryMB, tapName); err != nil {
		_ = vmCmd.Process.Kill()
		_ = vmCmd.Wait()
		_ = os.RemoveAll(filepath.Dir(chrootDir))
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
		_ = vmCmd.Process.Kill()
		_ = vmCmd.Wait()
		_ = os.RemoveAll(filepath.Dir(chrootDir))
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
		_ = cmd.Wait()
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
	errs := teardownFirecrackerRun(ctx.RunID, &fcRunState{
		RunID:    ctx.RunID,
		VMPid:    ctx.VMPid,
		SquidPID: ctx.SquidPID,
	})

	// Reap the child if this process started it, so no zombie remains.
	if cmd, ok := f.vmCmds[ctx.RunID]; ok {
		_ = cmd.Wait()
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
//
// credEnv carries the credentials the Agentfile declared (empty when it
// declared none); gateEnv carries the CONSTLE_MCP_<ID>_URL and CONSTLE_A2A_URL
// gate addresses, and the NO_PROXY exemption for them (empty when no gates are
// bound).
func buildWorkspaceImage(runDir string, m *manifest.AgentManifest, gatewayIP, guestIP string, credEnv, gateEnv map[string]string) (string, error) {
	staging := filepath.Join(runDir, "ws")
	if err := os.MkdirAll(staging, 0700); err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(staging) }()

	envFile, err := renderGuestEnvFile(guestEnv(gatewayIP, guestIP, credEnv, gateEnv))
	if err != nil {
		return "", err
	}
	// 0600: the env file may carry API keys. The image itself stays inside
	// the root-owned chroot and is deleted by Stop.
	if err := os.WriteFile(filepath.Join(staging, "env"), []byte(envFile), 0600); err != nil {
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
	// 0600 from the moment the inode exists, not after the fact. The image
	// carries the env blob with the run's API keys and gate tokens, and it
	// is built here in the 0755 run directory before prepareChroot renames
	// it into the 0700 jail — os.Create's 0666&umask left it world-readable
	// for exactly that window, which is long enough to copy it out of. The
	// mode is restated below because a lax umask cannot widen it, only a
	// strict one narrow it, and the guest must still be able to write.
	f, err := os.OpenFile(workspacePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return "", err
	}
	// 256 MB: room for the agent log alongside env+cmd.
	if err := f.Truncate(256 * 1024 * 1024); err != nil {
		// The truncate error is the one that explains the failure; this
		// close only releases a handle to an image already being abandoned.
		_ = f.Close()
		return "", err
	}
	// mkfs.ext4 below reads this file back from disk, so the image must
	// actually be there — a close that failed means it may not be.
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("cannot finalize workspace image: %w", err)
	}

	if out, err := exec.Command("mkfs.ext4", "-q", "-F", "-d", staging, workspacePath).CombinedOutput(); err != nil {
		return "", cmdError("mkfs.ext4", err, out)
	}
	return workspacePath, nil
}

// guestEnv composes the environment the microVM receives, in the one order
// that is safe: declared credentials first, then the variables this run built.
//
// Everything after the credentials is infrastructure the guest needs in order
// to be reachable and contained — the per-run Squid address, its own network
// parameters, and the gate URLs, which carry this run's gate token — and a
// manifest must not be able to replace any of it.
//
// The host variables used to be merged OVER the proxy and guest-network block,
// which was harmless only because the forwarded names were a hardcoded list of
// three. The moment the names come from the Agentfile, that order let
// `credentials: [{name: HTTP_PROXY}]` hand the guest a proxy address of the
// operator's choosing, and `{name: CONSTLE_GUEST_CIDR}` misstate its own
// network to it.
//
// The gate URLs were never exposed that way — gateEnv was applied last then as
// it is now — and that is the point of stating the whole order here rather than
// only fixing the half that was wrong: both properties now come from one
// visible sequence instead of one being deliberate and the other incidental.
//
// manifest.Validate refuses every name in this class (ReservedCredentialName)
// and credentials.Resolve refuses it again; this order is what holds when
// neither has run.
//
// Split out from buildWorkspaceImage so that invariant can be asserted by a
// unit test with no mkfs.ext4, no debugfs and no root — the same reason
// proxyRunArgs is split out of startProxyContainer.
func guestEnv(gatewayIP, guestIP string, credEnv, gateEnv map[string]string) map[string]string {
	env := make(map[string]string, len(credEnv)+len(gateEnv)+6)
	for k, v := range credEnv {
		env[k] = v
	}
	// Every reserved proxy name is set, including the ones this backend has no
	// use of its own for. The names are reserved precisely so a manifest cannot
	// supply them; a name that is reserved but never written is reserved in the
	// validator only, and the ordering below would leave a credential of that
	// name standing — which is what happened to NO_PROXY on a run with no gate
	// bound, and to ALL_PROXY and FTP_PROXY on every run. Found by independent
	// review of this change.
	//
	// NO_PROXY is empty here and overwritten by gateEnv when a gate is bound;
	// that is the one exemption this backend has, and it is the gate address.
	proxyURL := fmt.Sprintf("http://%s:%d", gatewayIP, fcSquidPort)
	for k, v := range map[string]string{
		"HTTP_PROXY":         proxyURL,
		"HTTPS_PROXY":        proxyURL,
		"http_proxy":         proxyURL,
		"https_proxy":        proxyURL,
		"ALL_PROXY":          proxyURL,
		"all_proxy":          proxyURL,
		"FTP_PROXY":          proxyURL,
		"ftp_proxy":          proxyURL,
		"NO_PROXY":           "",
		"no_proxy":           "",
		"CONSTLE_GUEST_CIDR": guestIP + "/30",
		"CONSTLE_GATEWAY_IP": gatewayIP,
	} {
		env[k] = v
	}
	for k, v := range gateEnv {
		env[k] = v
	}
	return env
}

// renderGuestEnvFile renders the guest's /env, which the guest sources as root
// before the agent runs.
//
// The value is single-quote escaped; the NAME cannot be, because a quoted name
// is not an assignment. So the name is CHECKED rather than escaped: a name
// carrying a quote, a semicolon or a newline would close the export statement
// and open another one, in a file that is about to be executed. Rendering
// refuses what it cannot represent instead of trusting what it was handed —
// the same second line buildSquidConfig keeps by re-checking every allowlist
// entry it writes, and it holds for a manifest that never went through
// Validate.
//
// Sorted, so the same environment renders to the same bytes every time.
func renderGuestEnvFile(env map[string]string) (string, error) {
	var out strings.Builder
	for _, k := range sortedKeys(env) {
		if err := manifest.ValidateCredentialName(k); err != nil {
			return "", fmt.Errorf("refusing to build the guest environment: variable name %q: %w", k, err)
		}
		fmt.Fprintf(&out, "export %s='%s'\n", k, strings.ReplaceAll(env[k], "'", `'\''`))
	}
	return out.String(), nil
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
	if err := copyImage(rootfsPath, filepath.Join(chroot, "rootfs.ext4")); err != nil {
		return "", err
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

// copyImage copies a disk image preserving sparseness where the host's cp
// supports it. --sparse=always is GNU coreutils; a busybox cp (Alpine and
// friends) rejects the flag, so an unrecognized-option failure retries as a
// plain copy — costing disk space, never correctness. Any other failure
// (disk full, permissions) is reported as-is, not retried.
func copyImage(src, dst string) error {
	out, err := exec.Command("cp", "--sparse=always", src, dst).CombinedOutput()
	if err == nil {
		return nil
	}
	if sparseFlagUnsupported(out) {
		if out, err := exec.Command("cp", src, dst).CombinedOutput(); err != nil {
			return cmdError("cannot copy rootfs", err, out)
		}
		return nil
	}
	return cmdError("cannot copy rootfs", err, out)
}

// sparseFlagUnsupported reports whether cp's failure output says the
// --sparse flag itself is the problem (a non-GNU cp), as opposed to the copy
// failing for a real reason.
func sparseFlagUnsupported(out []byte) bool {
	msg := strings.ToLower(string(out))
	return strings.Contains(msg, "sparse") &&
		(strings.Contains(msg, "unrecognized") || strings.Contains(msg, "invalid option") ||
			strings.Contains(msg, "unknown option") || strings.Contains(msg, "illegal option"))
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
