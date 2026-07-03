package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogWritesJSONL(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.jsonl")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer logger.Close()

	err = logger.Log("run-123", "test-agent", EventRunStarted, map[string]any{
		"backend": "docker",
	})
	if err != nil {
		t.Fatalf("Log() error: %v", err)
	}

	err = logger.Log("run-123", "test-agent", EventRunFinished, map[string]any{
		"duration_ms": 1500,
	})
	if err != nil {
		t.Fatalf("Log() error: %v", err)
	}

	logger.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	for i, line := range lines {
		var entry Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i+1, err)
		}
	}

	var first Entry
	json.Unmarshal([]byte(lines[0]), &first)
	if first.Event != EventRunStarted {
		t.Errorf("first event = %q, want %q", first.Event, EventRunStarted)
	}
	if first.RunID != "run-123" {
		t.Errorf("run_id = %q, want %q", first.RunID, "run-123")
	}
	if first.AgentName != "test-agent" {
		t.Errorf("agent_name = %q, want %q", first.AgentName, "test-agent")
	}

	if first.Timestamp.IsZero() {
		t.Error("timestamp is zero")
	}
}

func TestLogCreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "a", "b", "c", "test.jsonl")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("New() should create missing dirs, got error: %v", err)
	}
	defer logger.Close()

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("log file was not created")
	}
}

func TestLogWithIsolation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.jsonl")

	logger, _ := New(logPath)
	defer logger.Close()

	logger.LogWithIsolation("run-456", "secure-agent", EventRunStarted, "kernel", nil)
	logger.Close()

	data, _ := os.ReadFile(logPath)
	var entry Entry
	json.Unmarshal(data, &entry)

	if entry.IsolationLevel != "kernel" {
		t.Errorf("isolation_level = %q, want \"kernel\"", entry.IsolationLevel)
	}
}

func TestDefaultLogPath(t *testing.T) {
	path := DefaultLogPath("my-agent")

	if !strings.Contains(path, ".constle") {
		t.Errorf("path %q should contain .constle", path)
	}
	if !strings.HasSuffix(path, ".jsonl") {
		t.Errorf("path %q should end with .jsonl", path)
	}
	if !strings.Contains(path, "my-agent") {
		t.Errorf("path %q should contain agent name", path)
	}
}
