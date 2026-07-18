package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSubnetForRunDeterministicAndAligned(t *testing.T) {
	gw1, guest1 := subnetForRun("a1b2c3d4e5f60708", 0)
	gw2, guest2 := subnetForRun("a1b2c3d4e5f60708", 0)

	if gw1 != gw2 || guest1 != guest2 {
		t.Errorf("subnetForRun is not deterministic: (%s,%s) vs (%s,%s)", gw1, guest1, gw2, guest2)
	}

	if !strings.HasPrefix(gw1, "172.30.") {
		t.Errorf("gateway %q not in 172.30.0.0/16", gw1)
	}

	var third, last int
	if _, err := fmt.Sscanf(gw1, "172.30.%d.%d", &third, &last); err != nil {
		t.Fatalf("cannot parse gateway %q: %v", gw1, err)
	}
	// Gateway must be .base+1 of a /30-aligned block.
	if (last-1)%4 != 0 {
		t.Errorf("gateway last octet %d is not /30-aligned (+1)", last)
	}

	var guestLast int
	fmt.Sscanf(guest1, "172.30.%d.%d", &third, &guestLast)
	if guestLast != last+1 {
		t.Errorf("guest %q should be gateway+1 (%d)", guest1, last+1)
	}
}

func TestSubnetForRunSaltVaries(t *testing.T) {
	gw0, _ := subnetForRun("a1b2c3d4e5f60708", 0)

	// At least one of the next few salts must move the subnet — otherwise
	// collision retry cannot work.
	for salt := 1; salt < 16; salt++ {
		if gw, _ := subnetForRun("a1b2c3d4e5f60708", salt); gw != gw0 {
			return
		}
	}
	t.Error("16 different salts produced the same subnet")
}

func TestSanitizeImageName(t *testing.T) {
	cases := map[string]string{
		"basic-agent:latest":       "basic-agent-latest",
		"curlimages/curl:latest":   "curlimages-curl-latest",
		"Python:3.12-Slim":         "python-3.12-slim",
		"ghcr.io/org/img@sha256:x": "ghcr.io-org-img-sha256-x",
	}
	for in, want := range cases {
		if got := sanitizeImageName(in); got != want {
			t.Errorf("sanitizeImageName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFCTAPNameLength(t *testing.T) {
	name := fcTAPName("a1b2c3d4e5f60708")
	if len(name) > 15 {
		t.Errorf("TAP name %q exceeds IFNAMSIZ-1 (15)", name)
	}
	if !strings.HasPrefix(name, "ct") {
		t.Errorf("TAP name %q should start with ct", name)
	}
	if name != "cta1b2c3d4e5f6" {
		t.Errorf("TAP name = %q, want cta1b2c3d4e5f6", name)
	}
}

func TestFCGuestMAC(t *testing.T) {
	mac := fcGuestMAC("a1b2c3d4e5f60708")
	if mac != "06:00:a1:b2:c3:d4" {
		t.Errorf("fcGuestMAC = %q, want 06:00:a1:b2:c3:d4", mac)
	}
}

func TestBuildSquidConfigFirecrackerVariant(t *testing.T) {
	config := buildSquidConfig("testrun01", []string{"api.groq.com"},
		"172.30.1.1:3128", "/var/lib/constle/runs/testrun01/access.log",
		"pid_filename none", "172.30.1.1", nil)

	for _, want := range []string{
		"http_port 172.30.1.1:3128",
		"access_log /var/lib/constle/runs/testrun01/access.log",
		"pid_filename none",
		"acl allowed_hosts dstdomain api.groq.com",
		"http_access deny all",
		"http_access deny ip_only !allowed_hosts",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("config missing %q", want)
		}
	}
}

func TestBuildSquidConfigEmptyDeniesAll(t *testing.T) {
	config := buildSquidConfig("testrun02", nil, "172.30.1.1:3128", "/tmp/x.log", "", "172.30.1.1", nil)

	if !strings.Contains(config, "http_access deny all") {
		t.Error("empty allowlist config must deny all traffic")
	}
	if strings.Contains(config, "http_access allow") {
		t.Error("empty allowlist config should not have any allow rules")
	}
}

func TestCmdlineMatches(t *testing.T) {
	// The test binary's own /proc entry is a live, guaranteed process.
	self := os.Getpid()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", self))
	if err != nil {
		t.Skipf("no /proc on this platform: %v", err)
	}
	argv0 := strings.SplitN(string(raw), "\x00", 2)[0]

	if !cmdlineMatches(self, filepath.Base(argv0), "") {
		t.Errorf("cmdlineMatches should match our own process %d (%s)", self, argv0)
	}
	if cmdlineMatches(self, "firecracker", "") {
		t.Error("cmdlineMatches must not match a non-firecracker binary name")
	}
	if cmdlineMatches(self, filepath.Base(argv0), "definitely-not-an-arg-of-this-process") {
		t.Error("cmdlineMatches must require the argument to be present")
	}
	if cmdlineMatches(0, "anything", "") || cmdlineMatches(-1, "anything", "") {
		t.Error("cmdlineMatches must reject non-positive PIDs")
	}
	if cmdlineMatches(1<<30, "anything", "") {
		t.Error("cmdlineMatches must be false for a non-existent PID")
	}
}

func TestFCProcessAliveRejectsDeadPID(t *testing.T) {
	if fcProcessAlive(1<<30, "a1b2c3d4e5f60708") {
		t.Error("fcProcessAlive must be false for a non-existent PID")
	}
}

func TestResolveRootfsFallsBackToDefault(t *testing.T) {
	// Point the lookup at a temp images dir via a direct call to the
	// convention: unknown image + no default → error mentioning setup.
	_, err := resolveRootfs("no-such-image:v9")
	if err != nil && !strings.Contains(err.Error(), "setup-firecracker") {
		t.Errorf("error should point at setup script, got: %v", err)
	}
	// On hosts where setup ran, the default rootfs resolves.
	if err == nil {
		path, _ := resolveRootfs("no-such-image:v9")
		if filepath.Base(path) != "default.ext4" {
			t.Errorf("unknown image should fall back to default.ext4, got %s", path)
		}
	}
}
