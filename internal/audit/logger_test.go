package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/constle/constle/internal/homedir"
)

func TestLogWritesJSONL(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.jsonl")

	logger, err := New(homedir.Under(dir, "test.jsonl"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer func() { _ = logger.Close() }()

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

	_ = logger.Close()

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
	_ = json.Unmarshal([]byte(lines[0]), &first)
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

	logger, err := New(homedir.Under(dir, "a", "b", "c", "test.jsonl"))
	if err != nil {
		t.Fatalf("New() should create missing dirs, got error: %v", err)
	}
	defer func() { _ = logger.Close() }()

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("log file was not created")
	}
}

func TestLogWithIsolation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.jsonl")

	logger, _ := New(homedir.Under(dir, "test.jsonl"))
	defer func() { _ = logger.Close() }()

	_ = logger.LogWithIsolation("run-456", "secure-agent", EventRunStarted, "kernel", nil)
	_ = logger.Close()

	data, _ := os.ReadFile(logPath)
	var entry Entry
	_ = json.Unmarshal(data, &entry)

	if entry.IsolationLevel != "kernel" {
		t.Errorf("isolation_level = %q, want \"kernel\"", entry.IsolationLevel)
	}
}

// A dropped entry is invisible to every later reader — verification proves
// the lines present are authentic, never that none is missing — so Err is the
// only way a caller learns the log is holed. It must report the FIRST failure
// and keep reporting it, since that is the entry whose loss is unrecoverable.
func TestErrRetainsFirstWriteFailure(t *testing.T) {
	logger, err := New(homedir.Under(t.TempDir(), "test.jsonl"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if err := logger.Log("run-1", "agent", EventRunStarted, nil); err != nil {
		t.Fatalf("Log() error: %v", err)
	}
	if err := logger.Err(); err != nil {
		t.Fatalf("Err() = %v after a successful write, want nil", err)
	}

	// Closing the file makes every later write fail, standing in for the
	// real causes (a full disk, a revoked mount).
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	firstFailure := logger.Log("run-1", "agent", EventGateDenied, nil)
	if firstFailure == nil {
		t.Fatal("Log() on a closed file returned nil, want an error")
	}
	if got := logger.Err(); got == nil {
		t.Fatal("Err() = nil after a failed write, want the failure")
	}

	// A second failure must not displace the first: the run is already
	// known-incomplete, and the earliest loss is the one worth naming.
	if err := logger.Log("run-1", "agent", EventRunFinished, nil); err == nil {
		t.Fatal("second Log() returned nil, want an error")
	}
	if got := logger.Err(); got.Error() != firstFailure.Error() {
		t.Errorf("Err() = %v, want the first failure %v", got, firstFailure)
	}
}

func TestDefaultLogLocation(t *testing.T) {
	loc, err := DefaultLogLocation("my-agent")
	if err != nil {
		t.Fatalf("DefaultLogLocation() error: %v", err)
	}

	path := loc.String()
	if !strings.Contains(path, ".constle") {
		t.Errorf("path %q should contain .constle", path)
	}
	if !strings.HasSuffix(path, ".jsonl") {
		t.Errorf("path %q should end with .jsonl", path)
	}
	if !strings.Contains(path, "my-agent") {
		t.Errorf("path %q should contain agent name", path)
	}
	// The home directory is the trusted base; .constle and logs are part of
	// the verified relative path, since the user controls both.
	if loc.Base != homedir.InvokingUserHome() {
		t.Errorf("Base = %q, want the invoking user's home %q", loc.Base, homedir.InvokingUserHome())
	}
	if !strings.HasPrefix(loc.Rel, filepath.Join(".constle", "logs")+string(filepath.Separator)) {
		t.Errorf("Rel = %q, want .constle/logs/<file>", loc.Rel)
	}
}

// A name carrying path separators or dot-segments must not produce a path
// outside ~/.constle/logs: New() creates that directory and, under sudo,
// chowns it to the invoking user, so an escaped path hands the user
// ownership of a directory it had no business touching.
func TestDefaultLogLocationRejectsEscapingNames(t *testing.T) {
	logsDir := filepath.Join(homedir.InvokingUserHome(), ".constle", "logs")

	// Only separator-bearing names can relocate the path here: a name of "."
	// or ".." still yields a direct child (".-<date>.jsonl"). Those are
	// rejected earlier, by identity.name validation in pkg/manifest.
	for _, name := range []string{
		"../../../../etc/constle",
		"../evil",
		"nested/agent",
		`..\windows`,
	} {
		loc, err := DefaultLogLocation(name)
		if err == nil {
			t.Errorf("DefaultLogLocation(%q) = %q, want an error — path escapes %s", name, loc, logsDir)
		}
		if loc != (homedir.Location{}) {
			t.Errorf("DefaultLogLocation(%q) returned %+v alongside its error, want the zero Location", name, loc)
		}
	}
}
