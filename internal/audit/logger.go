package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/constle/constle/internal/homedir"
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
	EventA2ACallSent       EventType = "a2a_call_sent"
	EventA2ACallReceived   EventType = "a2a_call_received"
	EventA2ACallRejected   EventType = "a2a_call_rejected"
	EventSpendingLimit     EventType = "spending_limit_reached"
	EventTerminatedByLimit EventType = "terminated_by_limit"
)

// Entry is a single JSONL audit log record.
//
// When the log is signed (the agent declares identity.did), every entry also
// carries DID, PrevHash, and Sig. Sig is declared last so that it marshals as
// the final JSON field: the signature covers the exact serialized bytes of
// the entry without the sig field, and a verifier recovers those bytes by
// trimming the `,"sig":"…"}` suffix from the raw line — no re-canonicalization,
// so verification is over the very bytes on disk.
type Entry struct {
	Timestamp      time.Time      `json:"timestamp"`
	RunID          string         `json:"run_id"`
	AgentName      string         `json:"agent_name"`
	Event          EventType      `json:"event"`
	Details        map[string]any `json:"details,omitempty"`
	IsolationLevel string         `json:"isolation_level,omitempty"`

	// DID is the did:key identifier whose private key signed this entry.
	DID string `json:"did,omitempty"`

	// PrevHash is the lowercase hex SHA-256 of the previous raw log line
	// (without the trailing newline), or GenesisHash for the first line of a
	// file. Because it is covered by Sig, deleting, editing, or reordering
	// any line breaks the chain — not just that line's own signature.
	PrevHash string `json:"prev_hash,omitempty"`

	// Sig is the base64 (std) Ed25519 signature over the serialized entry
	// with Sig itself absent. MUST remain the last declared field.
	Sig string `json:"sig,omitempty"`
}

// GenesisHash is the PrevHash of the first entry in a signed log file: an
// all-zero value no real SHA-256 output collides with in practice.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Signer signs audit entries on behalf of an agent identity. Implemented by
// *identity.Identity; defined here so audit does not depend on the identity
// package.
type Signer interface {
	// DID returns the signer's did:key identifier — the verification key is
	// recoverable from this string alone.
	DID() string
	// Sign returns the Ed25519 signature over message.
	Sign(message []byte) []byte
}

// Logger writes audit entries to a JSONL file, signing and hash-chaining
// them when a Signer is attached.
type Logger struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	signer   Signer
	lastHash string
}

// New creates a Logger that writes to path, creating the directory if needed.
// Entries are written unsigned; use NewSigned when the agent has an identity.
//
// Under sudo (required by the Firecracker backend) the log directory and
// file are handed back to the invoking user, so a sudo run never blocks a
// later non-sudo run from writing the same agent's log.
func New(path string) (*Logger, error) {
	dir := filepath.Dir(path)
	if err := homedir.MkdirAllOwned(dir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create log directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("cannot open log file %q: %w", path, err)
	}

	// Chown the directory too (not only created levels): it heals a dir left
	// root-owned by runs that predate this ownership restoration.
	if err := homedir.ChownToInvokingUser(dir, path); err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot restore log ownership to the invoking user: %w", err)
	}

	return &Logger{file: f, path: path}, nil
}

// NewSigned creates a Logger that signs and hash-chains every entry with the
// given signer. When the file already has entries (earlier runs the same
// day), the chain resumes from the hash of the last existing line, so one
// file holds one continuous chain across runs.
func NewSigned(path string, signer Signer) (*Logger, error) {
	if signer == nil {
		return nil, fmt.Errorf("NewSigned requires a signer")
	}

	l, err := New(path)
	if err != nil {
		return nil, err
	}

	lastHash, err := lastLineHash(path)
	if err != nil {
		l.file.Close()
		return nil, fmt.Errorf("cannot resume hash chain from %q: %w", path, err)
	}

	l.signer = signer
	l.lastHash = lastHash
	return l, nil
}

// Signed reports whether this logger signs and hash-chains its entries.
func (l *Logger) Signed() bool {
	return l.signer != nil
}

// Write appends one Entry to the log file, signing and chaining it when the
// logger has a signer.
func (l *Logger) Write(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.signer != nil {
		entry.DID = l.signer.DID()
		entry.PrevHash = l.lastHash
		entry.Sig = ""

		// Sign the serialized entry without the sig field; because Sig is the
		// last declared field, the final line is exactly these bytes with the
		// `,"sig":"…"}` suffix — verifiers check the signature against the raw
		// line bytes minus that suffix.
		unsigned, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("cannot marshal log entry: %w", err)
		}
		entry.Sig = base64.StdEncoding.EncodeToString(l.signer.Sign(unsigned))
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("cannot marshal log entry: %w", err)
	}

	if _, err := fmt.Fprintf(l.file, "%s\n", data); err != nil {
		return err
	}

	if l.signer != nil {
		sum := sha256.Sum256(data)
		l.lastHash = hex.EncodeToString(sum[:])
	}
	return nil
}

// lastLineHash returns the SHA-256 hex of the last non-empty line of the
// file, or GenesisHash when the file is empty or absent.
func lastLineHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return GenesisHash, nil
		}
		return "", err
	}

	var last []byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			last = line
		}
	}
	if last == nil {
		return GenesisHash, nil
	}
	sum := sha256.Sum256(last)
	return hex.EncodeToString(sum[:]), nil
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
	home := homedir.InvokingUserHome()
	date := time.Now().UTC().Format("2006-01-02")
	filename := fmt.Sprintf("%s-%s.jsonl", agentName, date)
	return filepath.Join(home, ".constle", "logs", filename)
}
