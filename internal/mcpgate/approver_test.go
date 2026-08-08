package mcpgate

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStdinIsTerminalRejectsNonTerminals pins the fail-closed half of the
// detection: none of the stdins a daemonized or piped run actually gets may be
// mistaken for a human at a keyboard, or Decide would block on a read that
// never resolves.
//
// The terminal case cannot be asserted here — `go test` never hands the test
// binary a real tty — so this covers the direction that is both testable and
// dangerous to get wrong. The opposite direction (a real console wrongly
// reported as non-interactive) is what the os.SameFile(os.DevNull) check used
// to get wrong on Windows; see stdinIsTerminal's comment.
func TestStdinIsTerminalRejectsNonTerminals(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("cannot open %s: %v", os.DevNull, err)
	}
	defer func() { _ = devNull.Close() }()

	regular, err := os.Create(filepath.Join(t.TempDir(), "stdin.txt"))
	if err != nil {
		t.Fatalf("cannot create temp file: %v", err)
	}
	defer func() { _ = regular.Close() }()

	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("cannot create pipe: %v", err)
	}
	defer func() { _ = pipeR.Close(); _ = pipeW.Close() }()

	cases := []struct {
		name string
		file *os.File
	}{
		{os.DevNull, devNull},
		{"regular file", regular},
		{"pipe", pipeR},
	}

	realStdin := os.Stdin
	defer func() { os.Stdin = realStdin }()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Stdin = tc.file
			if stdinIsTerminal() {
				t.Errorf("stdinIsTerminal() = true for %s, want false", tc.name)
			}
		})
	}
}

// TestNewTerminalApproverIsNonInteractiveUnderTest checks the wiring, not just
// the predicate: NewTerminalApprover must carry the detection result into
// Interactive, so a gate built in a non-terminal context resolves by timeout
// instead of prompting.
func TestNewTerminalApproverIsNonInteractiveUnderTest(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("cannot open %s: %v", os.DevNull, err)
	}
	defer func() { _ = devNull.Close() }()

	realStdin := os.Stdin
	defer func() { os.Stdin = realStdin }()
	os.Stdin = devNull

	if a := NewTerminalApprover(os.Stdout); a.Interactive {
		t.Error("NewTerminalApprover().Interactive = true with stdin on /dev/null, want false")
	}
}
