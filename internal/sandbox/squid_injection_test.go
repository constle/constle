package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteSquidConfigRejectsDirectiveInjection is the regression test for
// the allowlist-nullifying injection: an allowed_hosts entry carrying a
// newline used to be joined verbatim into the dstdomain line, so the text
// after the newline became a directive of its own, ahead of every deny
// rule. The config writer must now refuse the entry and write nothing.
func TestWriteSquidConfigRejectsDirectiveInjection(t *testing.T) {
	const runID = "injectrun01"
	hosts := []string{"api.example.com", "example.com\nhttp_access allow all"}
	expectedPath := filepath.Join(os.TempDir(), "constle-squid-"+runID+".conf")
	_ = os.Remove(expectedPath)

	path, err := writeSquidConfig(runID, hosts, "192.168.65.254", []int{41234})
	if err == nil {
		defer func() { _ = os.Remove(path) }()
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("ReadFile() error: %v", readErr)
		}
		for _, line := range strings.Split(string(content), "\n") {
			if strings.TrimSpace(line) == "http_access allow all" {
				t.Fatalf("injected directive rendered as its own line:\n%s", content)
			}
		}
		t.Fatal("writeSquidConfig() accepted a host carrying a newline")
	}
	// The whole entry, not just "example.com" — which the valid neighbour
	// also contains, so a validator that rejected everything would pass.
	if !strings.Contains(err.Error(), `"example.com\nhttp_access allow all"`) {
		t.Errorf("error should name the injected entry, got: %v", err)
	}
	if _, statErr := os.Stat(expectedPath); statErr == nil {
		_ = os.Remove(expectedPath)
		t.Fatalf("config file %s must not be written for a rejected allowlist", expectedPath)
	}
}

// TestStartHostSquidRejectsDirectiveInjection covers the same hole on the
// Firecracker backend, where the config is parsed by the host's own Squid
// running as root — an injected directive there reaches further than the
// allowlist. The rejection happens before anything is written or executed,
// so this needs neither root nor a squid binary.
func TestStartHostSquidRejectsDirectiveInjection(t *testing.T) {
	stubSquidDetection(t, squidVersionDebian, "proxy")
	runDir := t.TempDir()

	hosts := []string{"api.example.com", "example.com\nhttp_access allow all"}
	pid, logPath, err := startHostSquid("injectfc01", runDir, "127.0.0.1", hosts, []int{41234})
	if err == nil {
		t.Fatalf("startHostSquid() accepted a host carrying a newline (pid %d, log %q)", pid, logPath)
	}
	if !strings.Contains(err.Error(), `"example.com\nhttp_access allow all"`) {
		t.Errorf("error should name the injected entry, got: %v", err)
	}
	if pid != 0 {
		t.Errorf("pid = %d, want 0 — no Squid may be started for a rejected allowlist", pid)
	}
	// Nothing may reach disk either: a squid.conf left behind would be
	// picked up by a later start, and the access log is pre-created.
	for _, name := range []string{"squid.conf", "access.log"} {
		if _, statErr := os.Stat(filepath.Join(runDir, name)); statErr == nil {
			t.Errorf("%s must not be written for a rejected allowlist", name)
		}
	}
}
