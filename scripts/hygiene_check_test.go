// hygiene_check_test.go drives the real scripts/hygiene-check.sh against a
// throwaway git repository. It exists to pin down one specific regression:
// GNU grep reports a binary-file match ("binary file X matches") on stderr
// with nothing on stdout, so scan_stream's original `grep ... | head` — which
// only captured stdout — read a binary file carrying a banned pattern as
// clean. The fix captures stderr too (2>&1 before the pipe).
//
// A text fixture with the same pattern is not enough to catch this: grep
// never treats it as binary, so it always went through the stdout path and
// would pass even with the bug present. Only a fixture containing a NUL byte
// (or other non-text content) forces grep into its binary-file code path.
package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// writeAndCommit adds name (with the given bytes) to the repo at dir and
// commits it.
func writeAndCommit(t *testing.T, dir, name string, content []byte, message string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", name, err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	runGit(t, dir, "add", name)
	runGit(t, dir, "commit", "-q", "-m", message)
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// bannedMarker assembles, at runtime, a phrase matching one of
// hygiene-check.sh's own GENERIC_PATTERNS entries. It is built from parts
// rather than written as a literal so this test file's own source text never
// contains the phrase — hygiene-check.sh scans full commit patches, including
// this file's diff, and a literal match here would make every commit
// touching this test fail the project's own pre-push hook.
func bannedMarker() string {
	return strings.Join([]string{"generated", "by", "Cla" + "ude"}, " ")
}

// hebrewWord builds a Hebrew fixture from code points at runtime, for the same
// reason bannedMarker assembles its phrase: this source file must not itself
// contain what hygiene-check.sh scans for, or the scanner trips over its own
// test suite.
func hebrewWord() string {
	return string([]rune{0x05E2, 0x05D1, 0x05E8, 0x05D9, 0x05EA})
}

// newFixtureRepo creates a fresh git repo with one clean, unrelated commit
// already in it.
func newFixtureRepo(t *testing.T) string {
	t.Helper()
	skipIfWindows(t)
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	writeAndCommit(t, dir, "README.md", []byte("just a normal project\n"), "initial commit")
	return dir
}

// runHygieneCheck runs the real script against repo in --tree mode, isolated
// from the invoking machine's own private pattern file — this test cares
// only about the generic, checked-in patterns.
func runHygieneCheck(t *testing.T, repo string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	script := repoFile(t, "hygiene-check.sh")
	cmd := exec.Command(script, args...)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CONSTLE_HYGIENE_PATTERNS=/nonexistent-for-test")
	var out, errOut strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run hygiene-check.sh: %v", err)
	}
	return out.String(), errOut.String(), code
}

// TestTreeCatchesAttributionPatternInBinaryFile is the regression test for
// the stderr-capture bug: a real binary file (a NUL byte forces grep's binary
// path) carrying a banned attribution phrase must fail the scan, not pass it
// silently. Before the 2>&1 fix, this test fails: exit 0 and no hits
// reported, because GNU grep's "binary file matches" notice landed on stderr
// only and scan_stream never looked there.
func TestTreeCatchesAttributionPatternInBinaryFile(t *testing.T) {
	repo := newFixtureRepo(t)

	// A real binary fixture: an embedded NUL byte plus arbitrary non-text
	// bytes around a banned marker, so grep classifies the file as binary
	// rather than text — a plain text file with the same string would never
	// exercise the code path this test is protecting. The marker is built
	// from parts at runtime, not written as a literal here, so this source
	// file itself never contains the phrase hygiene-check.sh watches for.
	marker := bannedMarker()
	payload := append([]byte{0x00, 0x01, 0x02, 0xFF}, []byte("noise "+marker+" noise")...)
	payload = append(payload, 0x00, 0x03)
	writeAndCommit(t, repo, "asset.bin", payload, "add binary asset")

	stdout, stderr, code := runHygieneCheck(t, repo, "--tree")
	combined := stdout + stderr

	if code == 0 {
		t.Fatalf("expected hygiene-check.sh --tree to fail on a binary file with a banned pattern, got exit 0\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(combined, "asset.bin") {
		t.Fatalf("expected the report to name asset.bin as the offending file\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestTreeCleanBinaryFilePasses is the control: a binary file with no banned
// content must not trip the scan, proving the fix does not turn every binary
// file into a false positive.
func TestTreeCleanBinaryFilePasses(t *testing.T) {
	repo := newFixtureRepo(t)

	payload := []byte{0x00, 0x01, 0x02, 0xFF, 0x00, 0x03, 0x04}
	writeAndCommit(t, repo, "clean.bin", payload, "add clean binary asset")

	stdout, stderr, code := runHygieneCheck(t, repo, "--tree")
	if code != 0 {
		t.Fatalf("expected a clean binary file to pass, got exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
}

// TestTreeCatchesAttributionPatternInTextFile keeps the original, unaffected
// text-file path covered so a future change cannot silently break it while
// fixing the binary path.
func TestTreeCatchesAttributionPatternInTextFile(t *testing.T) {
	repo := newFixtureRepo(t)
	writeAndCommit(t, repo, "notes.txt", []byte("this was "+bannedMarker()+"\n"), "add notes")

	stdout, stderr, code := runHygieneCheck(t, repo, "--tree")
	combined := stdout + stderr

	if code == 0 {
		t.Fatalf("expected hygiene-check.sh --tree to fail on a text file with a banned pattern, got exit 0\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(combined, "notes.txt") {
		t.Fatalf("expected the report to name notes.txt as the offending file\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestTreeBinaryFileWithHebrewBytesPasses pins the narrowing the Hebrew check
// needed after the stderr-capture fix (PR #42) made binary matches visible at
// all. The check is a raw byte-range match, and compressed content hits that
// range by chance: the repo's own brand GIFs carry ~1900 matches each, every
// one a false positive. A scan that is permanently red is a scan nobody reads,
// which is the failure mode that lets a real hit through — so Hebrew is not
// looked for in binary content.
func TestTreeBinaryFileWithHebrewBytesPasses(t *testing.T) {
	repo := newFixtureRepo(t)

	// A NUL byte to force binary classification, then bytes inside the UTF-8
	// Hebrew ranges (D6 90–BF, D7 80–BF) exactly as LZW output lands in them.
	payload := []byte{0x00, 0x01, 0xD6, 0x90, 0xFF, 0xD7, 0xA9, 0x02, 0xD7, 0x9C, 0x00}
	writeAndCommit(t, repo, "brand.gif", payload, "add binary asset with incidental Hebrew bytes")

	stdout, stderr, code := runHygieneCheck(t, repo, "--tree")
	if code != 0 {
		t.Fatalf("expected a binary file with incidental Hebrew bytes to pass, got exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	// Skipped, not silent: a blind spot nobody is told about is how the
	// stderr bug survived as long as it did.
	if combined := stdout + stderr; !strings.Contains(combined, "brand.gif") {
		t.Fatalf("expected the report to say brand.gif was scanned as binary\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestTreeCatchesHebrewInTextFile is the other half: narrowing the check to
// text must not weaken it there, where leaked prose actually lives.
func TestTreeCatchesHebrewInTextFile(t *testing.T) {
	repo := newFixtureRepo(t)
	writeAndCommit(t, repo, "notes.md", []byte("a line of "+hebrewWord()+" prose\n"), "add notes")

	stdout, stderr, code := runHygieneCheck(t, repo, "--tree")
	combined := stdout + stderr

	if code == 0 {
		t.Fatalf("expected hygiene-check.sh --tree to fail on a text file containing Hebrew, got exit 0\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(combined, "notes.md") {
		t.Fatalf("expected the report to name notes.md as the offending file\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestTreeCatchesAttributionInBinaryWithHebrewBytes is the trap the narrowing
// could have walked into: skipping the Hebrew check on a binary must not skip
// the attribution check with it.
func TestTreeCatchesAttributionInBinaryWithHebrewBytes(t *testing.T) {
	repo := newFixtureRepo(t)

	payload := append([]byte{0x00, 0xD6, 0x90, 0xD7, 0xA9}, []byte("noise "+bannedMarker()+" noise")...)
	payload = append(payload, 0x00, 0xD7, 0x9C)
	writeAndCommit(t, repo, "credits.gif", payload, "add binary asset with an attribution phrase")

	stdout, stderr, code := runHygieneCheck(t, repo, "--tree")
	combined := stdout + stderr

	if code == 0 {
		t.Fatalf("expected a binary file carrying a banned pattern to fail even though Hebrew is skipped, got exit 0\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(combined, "credits.gif") {
		t.Fatalf("expected the report to name credits.gif as the offending file\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}
