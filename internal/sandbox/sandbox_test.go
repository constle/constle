package sandbox

import (
	"os"
	"strings"
	"testing"
)

func TestWriteSquidConfigWithHosts(t *testing.T) {
	path, err := writeSquidConfig("testrun01", []string{"api.openai.com", "arxiv.org"})
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
	path, err := writeSquidConfig("testrun02", []string{})
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

func TestDockerBackendIntegration(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("Docker not available — skipping integration test")
	}

	t.Skip("integration test — will be enabled after CLI wiring")
}
