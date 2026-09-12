package main

import (
	"io"
	"os"
	"testing"

	"github.com/constle/constle/internal/sandbox"
)

// `constle stop` runs as root for Firecracker runs and turns its argument
// into container names, a state-file path, a chroot path, a TAP device and
// an nftables table. The argument comes straight from the command line, so
// anything that is not a run ID must be refused with the validation error
// itself, before it is used for anything.
func TestCmdStopRejectsMalformedRunID(t *testing.T) {
	// A regression here would fall through to `docker rm` and `docker
	// network rm` against the developer's daemon; an empty PATH turns that
	// into a fast exec failure instead.
	t.Setenv("PATH", t.TempDir())

	for _, bad := range []string{
		"../../../../tmp/evil",
		"..",
		"76935e132f9be8e9/../evil",
		`..\..\evil`,
		"76935e132f9be8e",  // 15 characters
		"76935E132F9BE8E9", // upper case is never minted
		"",
	} {
		want := sandbox.ValidateRunID(bad)
		if want == nil {
			t.Fatalf("test bug: %q passes ValidateRunID", bad)
		}
		err := cmdStop(bad)
		if err == nil || err.Error() != want.Error() {
			t.Errorf("cmdStop(%q) error = %v, want exactly %q", bad, err, want)
		}
	}
}

// The rejection happens before any output, so a script sees only the error
// and an attacker-chosen string is never echoed to the terminal.
func TestCmdStopRejectsBeforeAnyOutput(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })

	const bad = "../../../../tmp/evil"
	cmdErr := cmdStop(bad)

	os.Stdout = orig
	_ = w.Close()
	out, _ := io.ReadAll(r)
	_ = r.Close()

	if cmdErr == nil {
		t.Fatalf("cmdStop(%q) = nil, want error", bad)
	}
	if len(out) != 0 {
		t.Errorf("cmdStop(%q) wrote %q to stdout before rejecting the ID", bad, out)
	}
}
