package sandbox

import (
	"strings"
	"testing"
)

// ValidateRunID guards every place a run ID becomes a path element, an
// interface name or a table name, so it must accept exactly what newRunID
// mints — 16 lowercase hex characters — and nothing that could carry a
// path segment, a flag or a stray byte past it.
func TestValidateRunID(t *testing.T) {
	for i := 0; i < 32; i++ {
		id, err := newRunID()
		if err != nil {
			t.Fatalf("newRunID: %v", err)
		}
		if err := ValidateRunID(id); err != nil {
			t.Errorf("ValidateRunID rejects a freshly minted ID %q: %v", id, err)
		}
	}
	if err := ValidateRunID("76935e132f9be8e9"); err != nil {
		t.Errorf("ValidateRunID(%q) = %v, want nil", "76935e132f9be8e9", err)
	}

	for _, bad := range []string{
		"",
		".",
		"..",
		"/",
		"../../../../tmp/evil",
		"../76935e132f9be8e9",
		"76935e132f9be8e9/..",
		"76935e132f9be8e9/../76935e132f9be8e9",
		`..\..\..\tmp\evil`,
		"76935e132f9be8e",   // 15 characters
		"76935e132f9be8e90", // 17 characters
		"76935E132F9BE8E9",  // upper case is never minted
		"76935e132f9be8eg",  // not hex
		"76935e132f9be8e9\n",
		"76935e132f9be8e9 ",
		" 76935e132f9be8e9",
		"76935e132f9be8e9\x00",
		"-f",
		"--",
	} {
		err := ValidateRunID(bad)
		if err == nil {
			t.Errorf("ValidateRunID(%q) = nil, want error", bad)
			continue
		}
		if !strings.Contains(err.Error(), "invalid run ID") {
			t.Errorf("ValidateRunID(%q) error = %q, want it to name the invalid run ID", bad, err)
		}
	}
}
