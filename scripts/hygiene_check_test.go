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

// ---------------------------------------------------------------------------
// Scoped patterns.
//
// hygiene-check.sh splits private patterns into two sets: entries checked in
// every file, and entries prefixed "text:" checked only in text content. The
// prefix exists for patterns written over raw byte ranges, which match
// compressed binary payloads by coincidence.
//
// These tests exercise the mechanism with an arbitrary sample range that has
// nothing to do with any range the project actually watches for. The real ones
// live in the private pattern file and are deliberately not restated here: a
// checked-in test that spelled one out would publish the thing the private
// file exists to keep out of the repo.
// ---------------------------------------------------------------------------

// sampleScopedPattern is a two-byte range, written as raw bytes the way a
// byte-range entry in a private pattern file is: C3 A0-BF, the tail of the
// Latin-1 supplement block in UTF-8.
func sampleScopedPattern() string {
	return string([]byte{0xC3, '[', 0xA0, '-', 0xBF, ']'})
}

// sampleScopedText is prose whose UTF-8 encoding lands inside that range.
func sampleScopedText() string {
	return string([]rune{0x00E9, 0x00E8, 0x00E0})
}

// writePrivatePatterns writes a private pattern file and returns its path.
// Raw bytes go in verbatim, exactly as the real file carries them.
func writePrivatePatterns(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "patterns")
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write pattern file: %v", err)
	}
	return path
}

// runHygieneCheckWith runs the script against a specific private pattern file
// rather than the absent one the other tests use.
func runHygieneCheckWith(t *testing.T, repo, patterns string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	script := repoFile(t, "hygiene-check.sh")
	cmd := exec.Command(script, args...)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CONSTLE_HYGIENE_PATTERNS="+patterns)
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

// TestByteRangeEntryAndItsNeighboursAllLoad is the regression test for a
// silent, partial failure of the private half of the scan.
//
// A byte-range entry puts improperly-encoded bytes in the private pattern
// file. grep then classifies that FILE as binary and stops reproducing its
// lines, so a loader reading it without -a drops the byte-range entry every
// time, and drops an unpredictable number of its neighbours along with it.
// Nothing reports this: the script carries on and prints a clean tree having
// checked a pattern set it never assembled.
//
// The fixture puts plain entries on both sides of the byte-range one and
// gives each of the three its own file to catch, so a partial load fails the
// test wherever the loss happens to land.
func TestByteRangeEntryAndItsNeighboursAllLoad(t *testing.T) {
	before, after := "zq"+"before"+"marker", "zq"+"after"+"marker"
	patterns := writePrivatePatterns(t, before, "text:"+sampleScopedPattern(), after)

	for _, tc := range []struct{ name, file, content string }{
		{"entry before the byte range", "one.txt", "a line with " + before},
		{"the byte range entry itself", "two.txt", "a line of " + sampleScopedText()},
		{"entry after the byte range", "three.txt", "a line with " + after},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFixtureRepo(t)
			writeAndCommit(t, repo, tc.file, []byte(tc.content+"\n"), "add fixture")

			stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree", "--require-private")
			combined := stdout + stderr

			if code == 0 {
				t.Fatalf("a private pattern was dropped on the way in: expected %s to be caught, got exit 0\nstdout:\n%s\nstderr:\n%s", tc.file, stdout, stderr)
			}
			if !strings.Contains(combined, tc.file) {
				t.Fatalf("expected the report to name %s\nstdout:\n%s\nstderr:\n%s", tc.file, stdout, stderr)
			}
		})
	}
}

// TestTreeCatchesScopedPatternInTextFile: narrowing a pattern to text must not
// weaken it there, which is where the content it looks for actually lives.
func TestTreeCatchesScopedPatternInTextFile(t *testing.T) {
	repo := newFixtureRepo(t)
	patterns := writePrivatePatterns(t, "text:"+sampleScopedPattern())
	writeAndCommit(t, repo, "notes.md", []byte("a line of "+sampleScopedText()+" prose\n"), "add notes")

	stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree", "--require-private")
	combined := stdout + stderr

	if code == 0 {
		t.Fatalf("expected a text file matching a text-scoped pattern to fail, got exit 0\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(combined, "notes.md") {
		t.Fatalf("expected the report to name notes.md\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestTreeBinarySkipsScopedPatterns: the same bytes inside a binary are
// coincidence, not content, and must not fail the scan — but the skip is
// announced rather than silent, because an unannounced blind spot is how the
// stderr bug survived as long as it did.
func TestTreeBinarySkipsScopedPatterns(t *testing.T) {
	repo := newFixtureRepo(t)
	patterns := writePrivatePatterns(t, "text:"+sampleScopedPattern())

	payload := append([]byte{0x00, 0x01}, []byte(sampleScopedText())...)
	payload = append(payload, 0xFF, 0x00)
	writeAndCommit(t, repo, "asset.gif", payload, "add binary asset")

	stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree", "--require-private")
	if code != 0 {
		t.Fatalf("expected a binary file with incidental in-range bytes to pass, got exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if combined := stdout + stderr; !strings.Contains(combined, "asset.gif") {
		t.Fatalf("expected the report to say asset.gif was scanned as binary\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestTreeCatchesAttributionInBinaryWithScopedBytes is the trap the scoping
// could have walked into: skipping the text-scoped patterns on a binary must
// not take the every-file patterns down with them.
func TestTreeCatchesAttributionInBinaryWithScopedBytes(t *testing.T) {
	repo := newFixtureRepo(t)
	patterns := writePrivatePatterns(t, "text:"+sampleScopedPattern())

	payload := append([]byte{0x00}, []byte(sampleScopedText())...)
	payload = append(payload, []byte(" noise "+bannedMarker()+" noise")...)
	payload = append(payload, 0x00, 0xFF)
	writeAndCommit(t, repo, "credits.gif", payload, "add binary asset")

	stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree", "--require-private")
	combined := stdout + stderr

	if code == 0 {
		t.Fatalf("expected a binary carrying a banned pattern to fail even though its scoped bytes are skipped, got exit 0\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(combined, "credits.gif") {
		t.Fatalf("expected the report to name credits.gif\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// gifWithMetadata builds a GIF-shaped fixture: a real header and logical
// screen descriptor, a comment extension (0x21 0xFE) carrying comment, the
// trailer byte, and then trailing bytes appended after it carrying trailer.
// Both are the positions real metadata occupies — container comment blocks
// and appended trailers are where EXIF/XMP-style text actually sits — and
// both are outside anything a viewer renders.
func gifWithMetadata(comment, trailer string) []byte {
	out := []byte("GIF89a")
	out = append(out, 0x10, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00) // screen descriptor
	out = append(out, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF)       // 2-colour table
	if comment != "" {
		out = append(out, 0x21, 0xFE, byte(len(comment)))
		out = append(out, []byte(comment)...)
		out = append(out, 0x00)
	}
	out = append(out, 0x3B) // trailer: the file ends here as far as a decoder is concerned
	if trailer != "" {
		out = append(out, []byte(trailer)...)
	}
	return out
}

// TestTreeCatchesAttributionInBinaryMetadata is the positive control for the
// half of binary scanning that DOES work. The every-file patterns are run
// against the whole byte stream, so a phrase in a container's metadata block,
// or in bytes appended after the image data, has to be found and named. If
// this ever passes, the binary path has stopped scanning rather than started
// being quiet about coincidences.
func TestTreeCatchesAttributionInBinaryMetadata(t *testing.T) {
	patterns := writePrivatePatterns(t, "text:"+sampleScopedPattern())

	for _, tc := range []struct{ name, comment, trailer string }{
		{"in a comment extension", bannedMarker(), ""},
		{"in bytes trailing the image", "", bannedMarker()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFixtureRepo(t)
			writeAndCommit(t, repo, "shot.gif", gifWithMetadata(tc.comment, tc.trailer), "add image")

			stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree", "--require-private")
			combined := stdout + stderr

			if code == 0 {
				t.Fatalf("expected a banned phrase in binary metadata to fail the scan, got exit 0\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
			}
			if !strings.Contains(combined, "shot.gif") {
				t.Fatalf("expected the report to name shot.gif\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
			}
		})
	}
}

// TestTreeScopedPatternInBinaryMetadataIsNotCaught pins the limitation
// documented on scan_stream, rather than leaving it to be rediscovered.
//
// Real text does live in binary metadata, and a text-scoped pattern does not
// reach it: the skip is applied to the whole file, and a byte-range pattern
// cannot tell a metadata block from compressed payload, so covering the first
// would re-admit the coincidental matches from the second. The scan is
// deliberately not extended. This test asserts the CURRENT behaviour so that
// changing it is a decision someone makes on purpose, and so the gap is
// visible in the suite instead of only in a comment.
//
// Consequence: binary metadata stays a hand check for anything the every-file
// patterns do not spell out.
func TestTreeScopedPatternInBinaryMetadataIsNotCaught(t *testing.T) {
	repo := newFixtureRepo(t)
	patterns := writePrivatePatterns(t, "text:"+sampleScopedPattern())
	writeAndCommit(t, repo, "shot.gif", gifWithMetadata(sampleScopedText(), ""), "add image")

	stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree", "--require-private")
	if code != 0 {
		t.Fatalf("this test documents a known gap; a non-zero exit means the gap was closed — update the comment on scan_stream and this test\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}
