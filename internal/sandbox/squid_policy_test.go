package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// squidBinary returns the squid executable, or "" when it is not installed.
// PATH alone is not enough: squid is a daemon and distributions install it in
// sbin, which is not on an ordinary user's PATH.
func squidBinary() string {
	if p, err := exec.LookPath("squid"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/squid", "/usr/local/sbin/squid", "/sbin/squid"} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

// TestGeneratedConfigParsesUnderRealSquid hands each shape of the generated
// configuration to the installed Squid and fails on anything it objects to.
//
// Every other test in this package asserts on the text of the config, which
// proves what was written and nothing about whether Squid accepts it. Nothing
// in CI ever parsed a config with a non-empty allowlist: the one test that
// starts a real Squid needs root and passes no allowed hosts, and the E2E
// suite is behind CONSTLE_E2E. A directive this file's Squid version does not
// know would pass every assertion here and then fail every run in the field,
// at startup, with the proxy the whole sandbox depends on.
//
// A complaint short of a fatal error counts too. Squid rewrote `dst 0.0.0.0/0`
// to `all` and announced it as a SECURITY NOTICE while exiting 0 — an ACL
// silently meaning something other than what it says is exactly the failure
// this test is for.
func TestGeneratedConfigParsesUnderRealSquid(t *testing.T) {
	squid := squidBinary()
	if squid == "" {
		t.Skip("squid not installed")
	}

	for _, tc := range []struct {
		name      string
		hosts     []string
		httpPort  string
		extra     string
		gateHost  string
		gatePorts []int
	}{
		{
			name:      "docker",
			hosts:     []string{"api.groq.com", ".example.com"},
			httpPort:  "3128",
			gateHost:  "host.docker.internal",
			gatePorts: []int{41234, 41235},
		},
		{
			name:      "firecracker",
			hosts:     []string{"api.groq.com"},
			httpPort:  "172.30.1.1:3128",
			extra:     "pid_filename none\nvisible_hostname constle-testrun01\nshutdown_lifetime 0 seconds",
			gateHost:  "172.30.1.1",
			gatePorts: []int{41234},
		},
		{
			name:      "no allowlist",
			httpPort:  "3128",
			gateHost:  "host.docker.internal",
			gatePorts: []int{41234},
		},
		{
			name:     "no gate",
			hosts:    []string{"api.groq.com"},
			httpPort: "3128",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := mustBuildSquidConfig(t, "testrun01", tc.hosts, tc.httpPort,
				filepath.Join(t.TempDir(), "access.log"), tc.extra, tc.gateHost, tc.gatePorts)

			path := filepath.Join(t.TempDir(), "squid.conf")
			if err := os.WriteFile(path, []byte(config), 0644); err != nil {
				t.Fatalf("write config: %v", err)
			}

			out, err := exec.Command(squid, "-k", "parse", "-f", path).CombinedOutput()
			if err != nil {
				t.Fatalf("squid -k parse rejected the config: %v\n%s\n--- config ---\n%s", err, out, config)
			}
			for _, line := range strings.Split(string(out), "\n") {
				upper := strings.ToUpper(line)
				for _, complaint := range []string{"ERROR", "FATAL", "WARNING", "SECURITY NOTICE", "UNRECOGNIZED"} {
					if strings.Contains(upper, complaint) {
						t.Errorf("squid objected to the config: %s\n--- config ---\n%s", line, config)
					}
				}
			}
		})
	}
}

// TestEveryNameACLDisablesReverseLookup pins F6. A dstdomain ACL without -n
// falls back to a reverse lookup when the destination is an IP literal and no
// value matches by string, and matches the PTR name against the allowlist —
// so an address whose reverse name is an allowlisted host was admitted, over
// GET and CONNECT alike, and that PTR record belongs to whoever owns the
// address. The gate's own ACL is covered for the same reason.
func TestEveryNameACLDisablesReverseLookup(t *testing.T) {
	config := mustBuildSquidConfig(t, "testrun01",
		[]string{"api.groq.com", ".example.com"}, "3128", "/tmp/x.log", "",
		"host.docker.internal", []int{41234})

	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "acl ") || !strings.Contains(line, "dstdomain") {
			continue
		}
		if !strings.Contains(line, "dstdomain -n ") {
			t.Errorf("name ACL without -n, reverse lookups still on: %q", line)
		}
	}
	for _, want := range []string{
		"acl allowed_hosts dstdomain -n api.groq.com\n",
		"acl allowed_hosts dstdomain -n .example.com\n",
		"acl constle_gate_dst dstdomain -n host.docker.internal\n",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("config missing %q:\n%s", want, config)
		}
	}
}

// TestInternalDestinationsAreDenied pins half of F5. The allowlist is matched
// by name, so the address a name resolves to was never examined: an entry
// pointing at 169.254.169.254 reached the cloud instance metadata service from
// the proxy container, and under Firecracker — where Squid runs on the host —
// 127.0.0.1 reached every service on that host. No manifest-time check can
// close this, because what a name resolves to is only known at run time.
func TestInternalDestinationsAreDenied(t *testing.T) {
	config := mustBuildSquidConfig(t, "testrun01", []string{"api.groq.com"},
		"3128", "/tmp/x.log", "", "host.docker.internal", []int{41234})

	if !strings.Contains(config, "http_access deny to_internal") {
		t.Fatalf("config never denies internal destinations:\n%s", config)
	}
	for _, cidr := range []string{
		"127.0.0.0/8",    // the sandbox host itself, on the Firecracker backend
		"169.254.0.0/16", // link-local, which is where cloud metadata lives
		"10.0.0.0/8",     // the three RFC 1918 ranges: the host's own network
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10", // CGNAT, routed inside many provider networks
		"0.0.0.0/8",     // 0.0.0.0, which several stacks treat as loopback
		"::1/128",       // and the IPv6 spellings of the same destinations
		"fe80::/10",
		"fc00::/7",
	} {
		if !strings.Contains(config, cidr) {
			t.Errorf("to_internal does not cover %s:\n%s", cidr, config)
		}
	}
}

// TestConnectIsConfinedToHTTPS pins the other half of F5. With no port rules
// at all, CONNECT to an allowlisted host on any port was a raw TCP tunnel out
// of the sandbox — the allowlist named the host, never the service.
func TestConnectIsConfinedToHTTPS(t *testing.T) {
	config := mustBuildSquidConfig(t, "testrun01", []string{"api.groq.com"},
		"3128", "/tmp/x.log", "", "host.docker.internal", []int{41234})

	for _, want := range []string{
		"acl SSL_ports port 443\n",
		"acl Safe_ports port 80 443\n",
		"http_access deny !Safe_ports\n",
		"http_access deny CONNECT !SSL_ports\n",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("config missing %q:\n%s", want, config)
		}
	}
}

// TestDenyRulesFollowTheGateAllow is the ordering invariant, and the one that
// makes the rules above safe to add at all. Squid takes the first http_access
// line that matches, and the gate sits on a private address (the Docker host
// relay, or the Firecracker TAP gateway) on an ephemeral port — so it matches
// to_internal, and it matches !Safe_ports. Either deny placed ahead of the
// gate's allow would cut the MCP and A2A gates off on both backends, and every
// gated tool call with them.
func TestDenyRulesFollowTheGateAllow(t *testing.T) {
	for _, gateHost := range []string{"host.docker.internal", "172.30.1.1"} {
		config := mustBuildSquidConfig(t, "testrun01", []string{"api.groq.com"},
			"3128", "/tmp/x.log", "", gateHost, []int{41234})

		ordered := []string{
			"http_access allow constle_gate_dst constle_gate_port",
			"http_access deny ip_only !allowed_hosts",
			"http_access deny to_internal",
			"http_access deny !Safe_ports",
			"http_access deny CONNECT !SSL_ports",
			"http_access allow allowed_hosts",
			"http_access deny all",
		}
		previous := -1
		for _, rule := range ordered {
			at := strings.Index(config, rule)
			if at < 0 {
				t.Fatalf("gateHost %s: config missing %q:\n%s", gateHost, rule, config)
			}
			if at <= previous {
				t.Errorf("gateHost %s: %q is out of order:\n%s", gateHost, rule, config)
			}
			previous = at
		}
	}
}

// TestNoNetworkConfigStillDeniesEverything: the empty-allowlist branch renders
// none of the rules above, so its only guarantee is the trailing deny. The
// gate clause is the single exception, and it must still be the only allow.
func TestNoNetworkConfigStillDeniesEverything(t *testing.T) {
	config := mustBuildSquidConfig(t, "testrun01", nil, "3128", "/tmp/x.log", "",
		"host.docker.internal", []int{41234})

	allows := 0
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "http_access allow") {
			allows++
			if !strings.Contains(line, "constle_gate_dst constle_gate_port") {
				t.Errorf("no-network config carries an allow beyond the gate route: %q", line)
			}
		}
	}
	if allows != 1 {
		t.Errorf("no-network config has %d allow rules, want exactly the gate route", allows)
	}
	if !strings.Contains(config, "http_access deny all") {
		t.Errorf("no-network config must end in deny all:\n%s", config)
	}
}
