package sandbox

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================
// firecracker_net.go — host-side network enforcement for microVM runs
//
// Security model: the guest is untrusted. All enforcement is host-side:
//
//   1. The TAP subnet is a /30 — the only two hosts are the gateway (host
//      side) and the guest. No IP forwarding, no NAT: packets from the
//      guest cannot be routed anywhere.
//   2. A per-run nftables table accepts exactly one flow — guest → gateway
//      IP on the Squid port — and drops everything else arriving on the
//      TAP, in both the input and forward hooks. DNS, ICMP, direct IPs:
//      all dropped.
//   3. Squid listens only on the gateway IP and enforces the manifest's
//      allowed_hosts ACL, exactly like the Docker backend's proxy.
//
// The per-run nftables table (constle_<runid>) is deleted as a unit on
// Stop, which removes all its chains and rules atomically.
// ============================================================

// subnetForRun deterministically derives a /30 subnet inside 172.30.0.0/16
// from the run ID. salt varies the result when the derived subnet collides
// with an interface that already exists on the host.
func subnetForRun(runID string, salt int) (gatewayIP, guestIP string) {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", runID, salt)))
	third := int(h[0])
	// Align the last octet to a /30 block: .base+1 = gateway, .base+2 = guest.
	base := int(h[1]) &^ 3
	return fmt.Sprintf("172.30.%d.%d", third, base+1), fmt.Sprintf("172.30.%d.%d", third, base+2)
}

// hostHasIP reports whether any host interface already carries ip.
func hostHasIP(ip string) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.String() == ip {
			return true
		}
	}
	return false
}

// createTAP creates the per-run TAP device, owned by the unprivileged VMM
// user so the jailed firecracker process can attach to it, and assigns the
// gateway address on the host side.
func createTAP(runID, tapName string) (gatewayIP, guestIP string, err error) {
	for salt := 0; salt < 256; salt++ {
		gatewayIP, guestIP = subnetForRun(runID, salt)
		if !hostHasIP(gatewayIP) {
			break
		}
		if salt == 255 {
			return "", "", fmt.Errorf("no free /30 subnet found in 172.30.0.0/16")
		}
	}

	if err := ipRun("tuntap", "add", tapName, "mode", "tap", "user", fcUser); err != nil {
		return "", "", err
	}
	if err := ipRun("addr", "add", gatewayIP+"/30", "dev", tapName); err != nil {
		deleteTAP(tapName)
		return "", "", err
	}
	if err := ipRun("link", "set", tapName, "up"); err != nil {
		deleteTAP(tapName)
		return "", "", err
	}
	return gatewayIP, guestIP, nil
}

// deleteTAP removes the TAP device. Missing devices are not an error —
// cleanup paths must be idempotent.
func deleteTAP(tapName string) error {
	out, err := exec.Command("ip", "link", "del", tapName).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "Cannot find device") {
		return fmt.Errorf("ip link del %s: %s", tapName, strings.TrimSpace(string(out)))
	}
	return nil
}

// nftTableName returns the per-run nftables table name.
func nftTableName(runID string) string {
	return "constle_" + runID
}

// installNFTRules installs the per-run enforcement table: the guest may
// reach the gateway's Squid port — plus each bound constle gate port (MCP,
// A2A) — and nothing else, in any hook.
func installNFTRules(runID, tapName, gatewayIP string, gatePorts []int) error {
	gateRule := ""
	for _, p := range gatePorts {
		gateRule += fmt.Sprintf("\t\tiifname %q ip daddr %s tcp dport %d accept\n",
			tapName, gatewayIP, p)
	}

	script := fmt.Sprintf(`table inet %[1]s {
	chain input {
		type filter hook input priority -10; policy accept;
		iifname %[2]q ip daddr %[3]s tcp dport %[4]d accept
%[5]s		iifname %[2]q drop
	}
	chain forward {
		type filter hook forward priority -10; policy accept;
		iifname %[2]q drop
	}
}
`, nftTableName(runID), tapName, gatewayIP, fcSquidPort, gateRule)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// deleteNFTRules removes the per-run table (and with it every chain and
// rule) atomically. A missing table is not an error.
func deleteNFTRules(runID string) error {
	out, err := exec.Command("nft", "delete", "table", "inet", nftTableName(runID)).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file or directory") {
		return fmt.Errorf("nft delete table: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// startHostSquid writes the per-run Squid config and starts a foreground
// Squid instance bound to the TAP gateway address. Returns the squid PID
// and the per-run access log path. Each gatePorts entry additionally allows
// proxied requests to that gate itself, for clients that route all traffic
// through http_proxy instead of honouring NO_PROXY.
func startHostSquid(runID, runDir, gatewayIP string, allowedHosts []string, gatePorts []int) (pid int, accessLogPath string, err error) {
	accessLogPath = filepath.Join(runDir, "access.log")
	configPath := filepath.Join(runDir, "squid.conf")

	extra := strings.Join([]string{
		"pid_filename none",
		"visible_hostname constle-" + runID,
		// Squid drops from root to this user; it must be able to write the log.
		"cache_effective_user proxy",
		// Exit immediately on SIGTERM — the default waits 30s for clients,
		// which would leave the per-run Squid lingering after Stop.
		"shutdown_lifetime 0 seconds",
	}, "\n")

	config := buildSquidConfig(runID, allowedHosts,
		fmt.Sprintf("%s:%d", gatewayIP, fcSquidPort), accessLogPath, extra,
		gatewayIP, gatePorts)
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		return 0, "", err
	}

	// Pre-create the access log writable by Squid's effective user, so the
	// run directory itself can stay root-owned.
	logFile, err := os.OpenFile(accessLogPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0, "", err
	}
	logFile.Close()
	if uid, gid, err := lookupSquidUser(); err == nil {
		os.Chown(accessLogPath, uid, gid)
	}

	cmd := exec.Command("squid", "-N", "-f", configPath)
	if err := cmd.Start(); err != nil {
		return 0, "", fmt.Errorf("squid start: %w", err)
	}
	// Reap in the background so no zombie remains when Stop kills it.
	go cmd.Wait()

	if err := waitForHostSquid(gatewayIP); err != nil {
		killPID(cmd.Process.Pid)
		return 0, "", err
	}
	return cmd.Process.Pid, accessLogPath, nil
}

// waitForHostSquid polls the proxy port until Squid accepts connections.
func waitForHostSquid(gatewayIP string) error {
	addr := net.JoinHostPort(gatewayIP, fmt.Sprint(fcSquidPort))
	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("squid did not become ready on %s after 15s", addr)
}

// lookupSquidUser resolves the user Squid drops privileges to (Debian/Ubuntu
// call it "proxy").
func lookupSquidUser() (uid, gid int, err error) {
	return lookupUserIDs("proxy")
}

// ipRun runs an ip(8) subcommand, returning stderr in the error like dockerRun.
func ipRun(args ...string) error {
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("ip %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}
