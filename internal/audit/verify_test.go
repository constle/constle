package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/constle/constle/internal/homedir"
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
	loc := homedir.Under(t.TempDir(), "signed.jsonl")
	path := loc.String()

	logger, err := NewSigned(loc, signer)
	if err != nil {
		t.Fatalf("NewSigned() error: %v", err)
	}
	defer func() { _ = logger.Close() }()

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
	logger, err := NewSigned(homedir.Under(filepath.Dir(path), filepath.Base(path)), signer)
	if err != nil {
		t.Fatalf("NewSigned() reopen error: %v", err)
	}
	if err := logger.Log("run-def", "test-agent", EventRunStarted, nil); err != nil {
		t.Fatalf("Log() error: %v", err)
	}
	_ = logger.Close()

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
	loc := homedir.Under(t.TempDir(), "unsigned.jsonl")
	path := loc.String()
	logger, err := New(loc)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := logger.Log("run-abc", "test-agent", EventRunStarted, nil); err != nil {
		t.Fatalf("Log() error: %v", err)
	}
	_ = logger.Close()

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

// TestTamperReportNeverEchoesAnUnvalidatedDID covers F81.
//
// VerifyFile decodes exactly one DID — the entry that fixes the log's
// identity, and only when the caller pinned nothing. Every other entry's
// `did` is compared as a string and, until this fix, spliced into the tamper
// report with %s: neither did.MaxLen nor the base58 alphabet had been applied
// to it. That value is arbitrary bytes out of a file designed to travel here
// from elsewhere, and encoding/json turns a `\u001b` escape into a real ESC
// even though it rejects a raw one.
//
// The fix is at the point the error is BUILT rather than the point it is
// printed, because VerifyFile is exported: an embedder that never touches
// constle's CLI must not inherit an error that can drive a terminal.
func TestTamperReportNeverEchoesAnUnvalidatedDID(t *testing.T) {
	victim := newTestSigner(t)

	hostile := `\u001b[2J\u001b[H\rAUDIT LOG VERIFIED`
	line := `{"timestamp":"2026-09-21T00:00:00Z","event":"run_started",` +
		`"did":"` + hostile + `","prev_hash":"deadbeef","sig":"AAAA"}`

	path := filepath.Join(t.TempDir(), "hostile.jsonl")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	_, err := VerifyFile(path, victim.did)
	var te *TamperError
	if !errors.As(err, &te) {
		t.Fatalf("VerifyFile() error = %v, want *TamperError", err)
	}
	if te.Kind != TamperDIDMismatch {
		t.Fatalf("got kind %q, want %q", te.Kind, TamperDIDMismatch)
	}

	// The premise: the file really does decode to a raw ESC, so a test that
	// found none would otherwise pass without proving anything.
	var entry Entry
	if uerr := json.Unmarshal([]byte(line), &entry); uerr != nil {
		t.Fatalf("premise unmarshal: %v", uerr)
	}
	if !strings.ContainsRune(entry.DID, 0x1B) {
		t.Fatal("premise wrong: the crafted entry carries no ESC after JSON decoding")
	}

	report := err.Error()
	for _, bad := range []rune{0x1B, 0x0D} {
		if strings.ContainsRune(report, bad) {
			t.Errorf("%U reached the tamper report verbatim: %q", bad, report)
		}
	}
	// Escaped, not dropped — the operator still sees what the entry claimed.
	if !strings.Contains(report, `\x1b[2J`) {
		t.Errorf("the offending value was hidden rather than quoted: %q", report)
	}
}

// TestTamperReportBoundsAnOversizedDID keeps one line of a log from becoming
// the whole error. Nothing caps the field before the comparison, so without a
// bound the report is as long as the attacker's file.
func TestTamperReportBoundsAnOversizedDID(t *testing.T) {
	victim := newTestSigner(t)

	huge := strings.Repeat("z", 8192)
	line := `{"timestamp":"2026-09-21T00:00:00Z","event":"run_started",` +
		`"did":"did:key:` + huge + `","prev_hash":"deadbeef","sig":"AAAA"}`

	path := filepath.Join(t.TempDir(), "huge.jsonl")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	_, err := VerifyFile(path, victim.did)
	if err == nil {
		t.Fatal("VerifyFile() error = nil, want a tamper report")
	}
	if n := len(err.Error()); n > 4*did.MaxLen {
		t.Errorf("tamper report is %d bytes for an %d-byte DID; the bound did not apply", n, len(huge))
	}
	if !strings.Contains(err.Error(), "bytes in all") {
		t.Errorf("an over-long DID should be reported by length: %q", err.Error())
	}
}
