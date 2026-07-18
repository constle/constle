package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/constle/constle/pkg/did"
)

// testSigner implements Signer over a raw Ed25519 key, standing in for
// *identity.Identity without importing the identity package.
type testSigner struct {
	did  string
	priv ed25519.PrivateKey
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}
	d, err := did.FromPublicKey(pub)
	if err != nil {
		t.Fatalf("FromPublicKey error: %v", err)
	}
	return &testSigner{did: d, priv: priv}
}

func (s *testSigner) DID() string            { return s.did }
func (s *testSigner) Sign(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }

// writeSignedLog produces a validly signed, hash-chained log with n entries
// and returns its path.
func writeSignedLog(t *testing.T, signer *testSigner, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signed.jsonl")

	logger, err := NewSigned(path, signer)
	if err != nil {
		t.Fatalf("NewSigned() error: %v", err)
	}
	defer logger.Close()

	events := []EventType{
		EventRunStarted, EventNetworkBlocked, EventNetworkAllowed,
		EventGateTriggered, EventGateApproved, EventGateDenied,
		EventGateTimeout, EventMCPToolBlocked, EventRunFinished,
	}
	for i := 0; i < n; i++ {
		err := logger.Log("run-abc", "test-agent", events[i%len(events)], map[string]any{
			"seq":  i,
			"host": "api.example.com",
		})
		if err != nil {
			t.Fatalf("Log() error: %v", err)
		}
	}
	return path
}

func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	var lines [][]byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}

func writeLines(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	if err := os.WriteFile(path, append(bytes.Join(lines, []byte("\n")), '\n'), 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
}

// tamperKindAt asserts that VerifyFile fails with the given kind at the
// given 1-based line.
func tamperKindAt(t *testing.T, path string, wantKind TamperKind, wantLine int) {
	t.Helper()
	_, err := VerifyFile(path, "")
	if err == nil {
		t.Fatal("VerifyFile() succeeded, want tamper error")
	}
	var te *TamperError
	if !errors.As(err, &te) {
		t.Fatalf("VerifyFile() error = %v, want *TamperError", err)
	}
	if te.Kind != wantKind {
		t.Errorf("tamper kind = %q, want %q (detail: %s)", te.Kind, wantKind, te.Detail)
	}
	if te.Line != wantLine {
		t.Errorf("tamper line = %d, want %d (detail: %s)", te.Line, wantLine, te.Detail)
	}
}

func TestVerifyUntouchedLog(t *testing.T) {
	signer := newTestSigner(t)
	path := writeSignedLog(t, signer, 9)

	report, err := VerifyFile(path, "")
	if err != nil {
		t.Fatalf("VerifyFile() error: %v", err)
	}
	if report.Entries != 9 {
		t.Errorf("Entries = %d, want 9", report.Entries)
	}
	if report.DID != signer.did {
		t.Errorf("DID = %q, want %q", report.DID, signer.did)
	}

	// Pinning the correct DID must also pass.
	if _, err := VerifyFile(path, signer.did); err != nil {
		t.Errorf("VerifyFile() with pinned DID error: %v", err)
	}
}

func TestVerifyChainResumesAcrossLoggerSessions(t *testing.T) {
	signer := newTestSigner(t)
	path := writeSignedLog(t, signer, 3)

	// A second run the same day appends to the same file; the chain must
	// continue from the last existing line, not restart at genesis.
	logger, err := NewSigned(path, signer)
	if err != nil {
		t.Fatalf("NewSigned() reopen error: %v", err)
	}
	if err := logger.Log("run-def", "test-agent", EventRunStarted, nil); err != nil {
		t.Fatalf("Log() error: %v", err)
	}
	logger.Close()

	report, err := VerifyFile(path, "")
	if err != nil {
		t.Fatalf("VerifyFile() after resume error: %v", err)
	}
	if report.Entries != 4 {
		t.Errorf("Entries = %d, want 4", report.Entries)
	}
}

func TestVerifyDetectsEditedField(t *testing.T) {
	signer := newTestSigner(t)
	path := writeSignedLog(t, signer, 5)

	lines := readLines(t, path)
	// Edit a details field in line 3 without touching signature or chain.
	edited := bytes.Replace(lines[2], []byte("api.example.com"), []byte("evil.example.com"), 1)
	if bytes.Equal(edited, lines[2]) {
		t.Fatal("test setup: edit did not change the line")
	}
	lines[2] = edited
	writeLines(t, path, lines)

	tamperKindAt(t, path, TamperInvalidSignature, 3)
}

func TestVerifyDetectsDeletedLine(t *testing.T) {
	signer := newTestSigner(t)
	path := writeSignedLog(t, signer, 5)

	lines := readLines(t, path)
	// Delete line 3; the old line 4 (now line 3) chains to a hash that no
	// longer exists anywhere in the file.
	writeLines(t, path, append(lines[:2], lines[3:]...))

	tamperKindAt(t, path, TamperMissingEntry, 3)
}

func TestVerifyDetectsReorderedLines(t *testing.T) {
	signer := newTestSigner(t)
	path := writeSignedLog(t, signer, 5)

	lines := readLines(t, path)
	// Swap lines 3 and 4. Every signature stays valid, but line 3 (old line
	// 4) now chains to a hash found elsewhere in the file — reordering, not
	// deletion.
	lines[2], lines[3] = lines[3], lines[2]
	writeLines(t, path, lines)

	tamperKindAt(t, path, TamperReordered, 3)
}

func TestVerifyDetectsDeletedFirstLine(t *testing.T) {
	signer := newTestSigner(t)
	path := writeSignedLog(t, signer, 3)

	lines := readLines(t, path)
	writeLines(t, path, lines[1:])

	// The new first line chains to the deleted line's hash, not genesis.
	tamperKindAt(t, path, TamperMissingEntry, 1)
}

func TestVerifyRejectsUnsignedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsigned.jsonl")
	logger, err := New(path)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := logger.Log("run-abc", "test-agent", EventRunStarted, nil); err != nil {
		t.Fatalf("Log() error: %v", err)
	}
	logger.Close()

	tamperKindAt(t, path, TamperMalformed, 1)
}

func TestVerifyRejectsFullRewriteUnderPinnedDID(t *testing.T) {
	// An attacker who rewrites the whole log — re-signing every line and
	// rebuilding the chain with their own key — produces an internally
	// consistent file. Only the DID gives them away: verification pinned to
	// the real agent DID must fail on line 1.
	victim := newTestSigner(t)
	attacker := newTestSigner(t)
	path := writeSignedLog(t, attacker, 4)

	if _, err := VerifyFile(path, ""); err != nil {
		t.Fatalf("attacker log should be internally consistent, got: %v", err)
	}

	_, err := VerifyFile(path, victim.did)
	var te *TamperError
	if !errors.As(err, &te) {
		t.Fatalf("VerifyFile() error = %v, want *TamperError", err)
	}
	if te.Kind != TamperDIDMismatch || te.Line != 1 {
		t.Errorf("got kind %q at line %d, want %q at line 1", te.Kind, te.Line, TamperDIDMismatch)
	}
}

func TestSignedEntriesCarryChainFields(t *testing.T) {
	signer := newTestSigner(t)
	path := writeSignedLog(t, signer, 2)

	lines := readLines(t, path)
	if !strings.Contains(string(lines[0]), `"prev_hash":"`+GenesisHash+`"`) {
		t.Errorf("first entry does not chain to the genesis hash: %s", lines[0])
	}
	for i, line := range lines {
		s := string(line)
		if !strings.Contains(s, `"did":"did:key:z`) || !strings.HasSuffix(s, `"}`) || !strings.Contains(s, `,"sig":"`) {
			t.Errorf("line %d is missing signing fields: %s", i+1, s)
		}
	}
}
