package audit

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr swaps os.Stderr for a pipe, runs fn, and returns what it
// wrote. WarnWriteFailure resolves os.Stderr at call time.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()

	fn()
	os.Stderr = orig
	_ = w.Close()
	return <-done
}

// TestWriteFailureWarningCannotDriveTheTerminal covers the path that makes
// this package print manifest data without ever meaning to.
//
// The audit log's filename is "<identity.name>-<date>.jsonl", and
// identity.name is free-form. A failed write on that file returns
// *fs.PathError, whose message quotes the path — so the warning that fires
// when the audit trail is already broken relays an Agentfile's bytes to the
// terminal, from a package that handles no display and interpolates only
// what it believes is an event constant.
//
// The error is produced by a real failed write rather than constructed, so
// the test still holds if the standard library changes what it puts in the
// message.
func TestWriteFailureWarningCannotDriveTheTerminal(t *testing.T) {
	hostile := filepath.Join(t.TempDir(), "agent\x1b[6n\r-2026-09-21.jsonl")

	f, err := os.OpenFile(hostile, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = f.Close() // the next write fails the way a full disk would
	_, writeErr := fmt.Fprintf(f, "entry\n")
	if writeErr == nil {
		t.Fatal("premise wrong: writing to a closed file succeeded")
	}
	if !strings.ContainsRune(writeErr.Error(), 0x1B) {
		t.Fatalf("premise wrong: the write error does not quote the path: %v", writeErr)
	}

	got := captureStderr(t, func() { WarnWriteFailure(EventRunStarted, writeErr) })

	for _, bad := range []rune{0x1B, 0x0D} {
		if strings.ContainsRune(got, bad) {
			t.Errorf("%U from the log filename reached the terminal: %q", bad, got)
		}
	}
	if !strings.Contains(got, "AUDIT WRITE FAILED") {
		t.Errorf("the warning itself went missing: %q", got)
	}
	if !strings.Contains(got, `\u001B[6n`) {
		t.Errorf("the filename was hidden rather than escaped: %q", got)
	}
	// Two lines, both constle's own: the relayed error cannot add one.
	if n := strings.Count(got, "\n"); n != 2 {
		t.Errorf("the warning spans %d lines, want 2: %q", n, got)
	}
}
