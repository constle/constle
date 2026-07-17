package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"
)

// EventType identifies the kind of event recorded in an audit log entry.
type EventType string

const (
	EventRunStarted        EventType = "run_started"
	EventRunFinished       EventType = "run_finished"
	EventRunFailed         EventType = "run_failed"
	EventGateTriggered     EventType = "gate_triggered"
	EventGateApproved      EventType = "gate_approved"
	EventGateDenied        EventType = "gate_denied"
	EventGateTimeout       EventType = "gate_timeout"
	EventNetworkBlocked    EventType = "network_blocked"
	EventNetworkAllowed    EventType = "network_allowed"
	EventMCPToolBlocked    EventType = "mcp_tool_blocked"
	EventSpendingLimit     EventType = "spending_limit_reached"
	EventTerminatedByLimit EventType = "terminated_by_limit"
)

// Entry is a single JSONL audit log record.
type Entry struct {
	Timestamp      time.Time      `json:"timestamp"`
	RunID          string         `json:"run_id"`
	AgentName      string         `json:"agent_name"`
	Event          EventType      `json:"event"`
	Details        map[string]any `json:"details,omitempty"`
	IsolationLevel string         `json:"isolation_level,omitempty"`
}

// Logger writes audit entries to a JSONL file.
type Logger struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// New creates a Logger that writes to path, creating the directory if needed.
func New(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("cannot create log directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("cannot open log file %q: %w", path, err)
	}

	return &Logger{file: f, path: path}, nil
}

// Write appends one Entry to the log file.
func (l *Logger) Write(entry Entry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("cannot marshal log entry: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	_, err = fmt.Fprintf(l.file, "%s\n", data)
	return err
}

// Log is a convenience wrapper that stamps the entry with the current UTC time.
func (l *Logger) Log(runID, agentName string, event EventType, details map[string]any) error {
	return l.Write(Entry{
		Timestamp: time.Now().UTC(),
		RunID:     runID,
		AgentName: agentName,
		Event:     event,
		Details:   details,
	})
}

// LogWithIsolation is like Log but also records the isolation level.
func (l *Logger) LogWithIsolation(runID, agentName string, event EventType, isolation string, details map[string]any) error {
	return l.Write(Entry{
		Timestamp:      time.Now().UTC(),
		RunID:          runID,
		AgentName:      agentName,
		Event:          event,
		IsolationLevel: isolation,
		Details:        details,
	})
}

// Close closes the underlying log file.
func (l *Logger) Close() error {
	return l.file.Close()
}

// Path returns the path of the log file.
func (l *Logger) Path() string {
	return l.path
}

// DefaultLogPath returns the default log file path for an agent.
//
// When constle runs under sudo (required by the Firecracker backend), the
// log still goes to the invoking user's home so all runs of an agent land
// in one place regardless of backend.
func DefaultLogPath(agentName string) string {
	home := invokingUserHome()
	date := time.Now().UTC().Format("2006-01-02")
	filename := fmt.Sprintf("%s-%s.jsonl", agentName, date)
	return filepath.Join(home, ".constle", "logs", filename)
}

// invokingUserHome resolves the home directory of the user who actually
// invoked constle, looking through sudo.
func invokingUserHome() string {
	if os.Geteuid() == 0 {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
			if u, err := user.Lookup(sudoUser); err == nil && u.HomeDir != "" {
				return u.HomeDir
			}
		}
	}
	home, _ := os.UserHomeDir()
	return home
}
