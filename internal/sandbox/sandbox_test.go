package sandbox

import (
	"os"
	"strings"
	"testing"
)

func TestWriteSquidConfigWithHosts(t *testing.T) {
	path, err := writeSquidConfig("testrun01", []string{"api.openai.com", "arxiv.org"}, "", 0)
	if err != nil {
		t.Fatalf("writeSquidConfig() error: %v", err)
	}
	defer os.Remove(path)

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	text := string(content)

	if !strings.Contains(text, "api.openai.com") {
		t.Error("config should contain api.openai.com")
	}
	if !strings.Contains(text, "arxiv.org") {
		t.Error("config should contain arxiv.org")
	}

	if !strings.Contains(text, "http_access deny all") {
		t.Error("config must have 'http_access deny all' as default deny")
	}

	if !strings.Contains(text, "http_access allow allowed_hosts") {
		t.Error("config should allow HTTP to allowed hosts")
	}
	if !strings.Contains(text, "http_access allow CONNECT allowed_hosts") {
		t.Error("config should allow HTTPS CONNECT to allowed hosts")
	}

	if !strings.Contains(path, "testrun01") {
		t.Errorf("config path %q should contain run ID", path)
	}
}

func TestWriteSquidConfigEmpty(t *testing.T) {
	path, err := writeSquidConfig("testrun02", []string{}, "", 0)
	if err != nil {
		t.Fatalf("writeSquidConfig() error: %v", err)
	}
	defer os.Remove(path)

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	text := string(content)

	if !strings.Contains(text, "http_access deny all") {
		t.Error("empty allowlist config must deny all traffic")
	}

	if strings.Contains(text, "http_access allow") {
		t.Error("empty allowlist config should not have any allow rules")
	}
}

func TestBuildSquidConfigMCPGateClause(t *testing.T) {
	// IP-literal gate host (both backends since the IPv6-preference fix)
	// must use a dst ACL, scoped to exactly the gate port, and must precede
	// the deny rules so the gate stays reachable with an empty allowlist.
	config := buildSquidConfig("testrun03", nil, "3128", "/tmp/x.log", "", "192.168.65.254", 41234)
	for _, want := range []string{
		"acl mcp_gate_dst dst 192.168.65.254",
		"acl mcp_gate_port port 41234",
		"http_access allow mcp_gate_dst mcp_gate_port",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("config missing %q:\n%s", want, config)
		}
	}
	if strings.Index(config, "http_access allow mcp_gate_dst") > strings.Index(config, "http_access deny all") {
		t.Error("gate allow rule must precede the deny-all rule")
	}

	// A hostname gate host uses dstdomain.
	config = buildSquidConfig("testrun04", []string{"api.openai.com"}, "3128", "/tmp/x.log", "", "gate.internal", 41234)
	if !strings.Contains(config, "acl mcp_gate_dst dstdomain gate.internal") {
		t.Errorf("hostname gate host should use dstdomain:\n%s", config)
	}

	// Port 0 (no MCP servers): no gate clause at all.
	config = buildSquidConfig("testrun05", nil, "3128", "/tmp/x.log", "", "", 0)
	if strings.Contains(config, "mcp_gate") {
		t.Errorf("config must have no gate clause when no gate is bound:\n%s", config)
	}
}

func TestNewRunID(t *testing.T) {
	id1, err := newRunID()
	if err != nil {
		t.Fatalf("newRunID() error: %v", err)
	}

	id2, err := newRunID()
	if err != nil {
		t.Fatalf("newRunID() error: %v", err)
	}

	// 8 bytes = 16 hex characters.
	if len(id1) != 16 {
		t.Errorf("run ID length = %d, want 16", len(id1))
	}

	if id1 == id2 {
		t.Error("two run IDs should not be identical")
	}

	for _, c := range id1 {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("run ID %q contains non-hex character %c", id1, c)
		}
	}
}

func TestHasListenerOnPort(t *testing.T) {
	// Real /proc/net/tcp excerpt: 0CEA (3306) in LISTEN (0A), 0C38 (3128)
	// only as an ESTABLISHED (01) remote peer.
	dump := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   111
   1: 0100007F:A3D2 0100007F:0C38 01 00000000:00000000 00:00000000 00000000  1000`

	if hasListenerOnPort(dump, 3128) {
		t.Error("3128 is not in LISTEN state — must not match remote peers or other states")
	}
	if !hasListenerOnPort(dump, 3306) {
		t.Error("3306 is listed in LISTEN state (0A) and should match")
	}

	listening := dump + "\n   2: 00000000:0C38 00000000:0000 0A 00000000:00000000 00:00000000 00000000   113"
	if !hasListenerOnPort(listening, 3128) {
		t.Error("3128 in LISTEN state should match")
	}
}

func TestDockerBackendIntegration(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("Docker not available — skipping integration test")
	}

	t.Skip("integration test — will be enabled after CLI wiring")
}
