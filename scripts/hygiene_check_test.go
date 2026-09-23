// hygiene_check_test.go drives the real scripts/hygiene-check.sh against a
// throwaway git repository and a throwaway pattern file. No real pattern is
// restated here: every marker below is synthetic, and the pattern files the
// tests write hold only those markers. What is tested is the mechanism.
//
// The first tests pin down one specific regression: GNU grep reports a
// binary-file match ("binary file X matches") on stderr with nothing on
// stdout, so scan_stream's original `grep ... | head` — which only captured
// stdout — read a binary file carrying a banned pattern as clean. The fix
// captures stderr too (2>&1 before the pipe).
//
// A text fixture with the same pattern is not enough to catch this: grep
// never treats it as binary, so it always went through the stdout path and
// would pass even with the bug present. Only a fixture containing a NUL byte
// (or other non-text content) forces grep into its binary-file code path.
//
// Later sections cover the pattern file itself, scoped patterns, commit
// metadata, and embedded file metadata.
package scripts_test

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/png"
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

// bannedMarker is the phrase the default test pattern file bans, checked in
// every scope. Like every marker in this file it is assembled from parts.
func bannedMarker() string {
	return "zq" + "banned" + "marker"
}

// metaMarker is banned by a meta: entry in the tests that use one: checked
// in embedded metadata and nowhere else.
func metaMarker() string {
	return "zq" + "metaonly" + "marker"
}

// writePrivatePatterns writes a pattern file and returns its path. Raw bytes
// go in verbatim, exactly as the real file carries them.
func writePrivatePatterns(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "patterns")
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write pattern file: %v", err)
	}
	return path
}

// exiftoolStub writes a stand-in for exiftool that reports having read the
// file and found nothing in it, and returns its path. The tests that are
// about the byte scan run against it, so they pass or fail on the same
// grounds on every host, with or without a real exiftool installed. The
// embedded-metadata tests below use the real one.
func exiftoolStub(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exiftool")
	body := "#!/bin/sh\necho '[ExifTool]      ExifToolVersion                 : 0.00'\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write exiftool stub: %v", err)
	}
	return path
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

// runHygieneCheck runs the real script against repo with a pattern file that
// bans bannedMarker and nothing else, isolated from the invoking machine's
// own pattern file. exiftool is the stub: see exiftoolStub.
func runHygieneCheck(t *testing.T, repo string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	return runHygieneCheckExif(t, repo, exiftoolStub(t), writePrivatePatterns(t, bannedMarker()), args...)
}

// runHygieneCheckWith runs the script against a specific pattern file.
// exiftool is the stub.
func runHygieneCheckWith(t *testing.T, repo, patterns string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	return runHygieneCheckExif(t, repo, exiftoolStub(t), patterns, args...)
}

// runHygieneCheckExif runs the script with the given exiftool and pattern
// file.
func runHygieneCheckExif(t *testing.T, repo, exiftool, patterns string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	script := repoFile(t, "hygiene-check.sh")
	cmd := exec.Command(script, args...)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(),
		"CONSTLE_HYGIENE_PATTERNS="+patterns,
		"CONSTLE_HYGIENE_EXIFTOOL="+exiftool,
	)
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

// TestTreeCatchesPatternInBinaryFile is the regression test for the
// stderr-capture bug: a real binary file (a NUL byte forces grep's binary
// path) carrying a banned phrase must fail the scan, not pass it silently.
// Before the 2>&1 fix, this test fails: exit 0 and no hits reported, because
// GNU grep's "binary file matches" notice landed on stderr only and
// scan_stream never looked there.
func TestTreeCatchesPatternInBinaryFile(t *testing.T) {
	repo := newFixtureRepo(t)

	// A real binary fixture: an embedded NUL byte plus arbitrary non-text
	// bytes around the marker, so grep classifies the file as binary rather
	// than text — a plain text file with the same string would never
	// exercise the code path this test is protecting.
	payload := append([]byte{0x00, 0x01, 0x02, 0xFF}, []byte("noise "+bannedMarker()+" noise")...)
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

// TestTreeCatchesPatternInTextFile keeps the original, unaffected text-file
// path covered so a future change cannot silently break it while fixing the
// binary path.
func TestTreeCatchesPatternInTextFile(t *testing.T) {
	repo := newFixtureRepo(t)
	writeAndCommit(t, repo, "notes.txt", []byte("this has "+bannedMarker()+" in it\n"), "add notes")

	stdout, stderr, code := runHygieneCheck(t, repo, "--tree")
	combined := stdout + stderr

	if code == 0 {
		t.Fatalf("expected hygiene-check.sh --tree to fail on a text file with a banned pattern, got exit 0\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(combined, "notes.txt") {
		t.Fatalf("expected the report to name notes.txt as the offending file\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestRangeCatchesPatternInCommitMessageAndIdentity: a commit is scanned as
// its author and committer lines and full message as well as its patch. The
// patch here is ordinary, so a hit can only have come from the other two.
func TestRangeCatchesPatternInCommitMessageAndIdentity(t *testing.T) {
	for _, tc := range []struct{ name, message, author string }{
		{"in the message", "fix a thing\n\nnoted by " + bannedMarker() + "\n", ""},
		{"in the author name", "fix a thing\n", "Pat " + bannedMarker() + " <pat@example.com>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFixtureRepo(t)
			if err := os.WriteFile(filepath.Join(repo, "change.txt"), []byte("an ordinary change\n"), 0o644); err != nil {
				t.Fatalf("write change.txt: %v", err)
			}
			runGit(t, repo, "add", "change.txt")
			args := []string{"commit", "-q", "-m", tc.message}
			if tc.author != "" {
				args = append(args, "--author", tc.author)
			}
			runGit(t, repo, args...)

			stdout, stderr, code := runHygieneCheck(t, repo, "--range", "HEAD~1..HEAD")
			if code != 1 {
				t.Fatalf("expected the commit to be caught (exit 1), got exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The pattern file.
//
// Nothing to scan for is built into the script, so the pattern file is not
// optional: a scan without one would look for nothing and report clean.
// ---------------------------------------------------------------------------

// TestMissingPatternFileIsRefused: no pattern file is a refusal, in every
// mode, with or without --require-private — never a clean report.
func TestMissingPatternFileIsRefused(t *testing.T) {
	repo := newFixtureRepo(t)
	missing := filepath.Join(t.TempDir(), "no-such-patterns")

	for _, args := range [][]string{{"--tree"}, {"--range", "HEAD~1..HEAD"}, {"--all"}, {"--tree", "--require-private"}} {
		stdout, stderr, code := runHygieneCheckExif(t, repo, exiftoolStub(t), missing, args...)
		combined := stdout + stderr
		if code != 2 {
			t.Fatalf("%v: expected a missing pattern file to be refused (exit 2), got exit %d\nstdout:\n%s\nstderr:\n%s", args, code, stdout, stderr)
		}
		if !strings.Contains(combined, "refusing to scan") || strings.Contains(combined, "working tree clean") {
			t.Fatalf("%v: expected a refusal and no clean report\nstdout:\n%s\nstderr:\n%s", args, stdout, stderr)
		}
	}
}

// TestPatternFileWithNoPatternsIsRefused: a file of comments and blank lines
// yields nothing to scan for, and is refused the same way.
func TestPatternFileWithNoPatternsIsRefused(t *testing.T) {
	repo := newFixtureRepo(t)
	patterns := writePrivatePatterns(t, "# nothing but a comment", "", "   ")

	stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree")
	if code != 2 || !strings.Contains(stdout+stderr, "contains no patterns") {
		t.Fatalf("expected a pattern file with no patterns to be refused (exit 2), got exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
}

// ---------------------------------------------------------------------------
// Scoped patterns.
//
// hygiene-check.sh splits the pattern file into three sets: entries checked
// everywhere, entries prefixed "text:" skipped on the raw bytes of a binary,
// and entries prefixed "meta:" checked in embedded metadata only. The text:
// prefix exists for patterns written over raw byte ranges, which match
// compressed binary payloads by coincidence.
//
// These tests exercise the mechanism with an arbitrary sample range that has
// nothing to do with any range the project actually watches for.
// ---------------------------------------------------------------------------

// sampleScopedPattern is a two-byte range, written as raw bytes the way a
// byte-range entry in a pattern file is: C3 A0-BF, the tail of the Latin-1
// supplement block in UTF-8.
func sampleScopedPattern() string {
	return string([]byte{0xC3, '[', 0xA0, '-', 0xBF, ']'})
}

// sampleScopedText is prose whose UTF-8 encoding lands inside that range.
func sampleScopedText() string {
	return string([]rune{0x00E9, 0x00E8, 0x00E0})
}

// TestByteRangeEntryAndItsNeighboursAllLoad is the regression test for a
// silent, partial failure of the pattern loader.
//
// A byte-range entry puts improperly-encoded bytes in the pattern file. grep
// then classifies that FILE as binary and stops reproducing its lines, so a
// loader reading it without -a drops the byte-range entry every time, and
// drops an unpredictable number of its neighbours along with it. Nothing
// reports this: the script carries on and prints a clean tree having checked
// a pattern set it never assembled.
//
// The fixture puts plain entries on both sides of the byte-range one and
// gives each of the three its own file to catch, so a partial load fails the
// test wherever the loss happens to land. A meta: entry rides along too: it
// catches nothing in these text files, but the load guard has to count it,
// or every run with one in the file is refused.
func TestByteRangeEntryAndItsNeighboursAllLoad(t *testing.T) {
	before, after := "zq"+"before"+"marker", "zq"+"after"+"marker"
	patterns := writePrivatePatterns(t, before, "text:"+sampleScopedPattern(), "meta:"+metaMarker(), after)

	for _, tc := range []struct{ name, file, content string }{
		{"entry before the byte range", "one.txt", "a line with " + before},
		{"the byte range entry itself", "two.txt", "a line of " + sampleScopedText()},
		{"entry after the byte range", "three.txt", "a line with " + after},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFixtureRepo(t)
			writeAndCommit(t, repo, tc.file, []byte(tc.content+"\n"), "add fixture")

			stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree")
			combined := stdout + stderr

			if code == 0 {
				t.Fatalf("a pattern was dropped on the way in: expected %s to be caught, got exit 0\nstdout:\n%s\nstderr:\n%s", tc.file, stdout, stderr)
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

	stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree")
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

	stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree")
	if code != 0 {
		t.Fatalf("expected a binary file with incidental in-range bytes to pass, got exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if combined := stdout + stderr; !strings.Contains(combined, "asset.gif") {
		t.Fatalf("expected the report to say asset.gif was scanned as binary\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestTreeCatchesPatternInBinaryWithScopedBytes is the trap the scoping could
// have walked into: skipping the text-scoped patterns on a binary must not
// take the every-file patterns down with them.
func TestTreeCatchesPatternInBinaryWithScopedBytes(t *testing.T) {
	repo := newFixtureRepo(t)
	patterns := writePrivatePatterns(t, bannedMarker(), "text:"+sampleScopedPattern())

	payload := append([]byte{0x00}, []byte(sampleScopedText())...)
	payload = append(payload, []byte(" noise "+bannedMarker()+" noise")...)
	payload = append(payload, 0x00, 0xFF)
	writeAndCommit(t, repo, "banner.gif", payload, "add binary asset")

	stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree")
	combined := stdout + stderr

	if code == 0 {
		t.Fatalf("expected a binary carrying a banned pattern to fail even though its scoped bytes are skipped, got exit 0\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(combined, "banner.gif") {
		t.Fatalf("expected the report to name banner.gif\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
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

// TestTreeCatchesPatternInBinaryMetadata is the positive control for the byte
// scan of a binary. The every-file patterns are run against the whole byte
// stream, so a phrase in a container's metadata block, or in bytes appended
// after the image data, has to be found and named — here with exiftool
// stubbed out, so the byte scan alone is what finds it.
func TestTreeCatchesPatternInBinaryMetadata(t *testing.T) {
	patterns := writePrivatePatterns(t, bannedMarker(), "text:"+sampleScopedPattern())

	for _, tc := range []struct{ name, comment, trailer string }{
		{"in a comment extension", bannedMarker(), ""},
		{"in bytes trailing the image", "", bannedMarker()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFixtureRepo(t)
			writeAndCommit(t, repo, "shot.gif", gifWithMetadata(tc.comment, tc.trailer), "add image")

			stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree")
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

// TestPrivateFileWithNoScopedEntriesLoads is the regression test for a bug
// that had nothing to do with any one platform, and that every earlier test
// missed because every earlier fixture happened to carry a text: entry.
//
// With no text: entry the scoped pattern file is empty, and the count guard
// counted it with `grep -c ” FILE || echo 0`. On an empty file grep prints 0
// AND exits 1, so the fallback fired too and the count came back as the
// two-line string "0\n0" — not a number, taking the arithmetic down with it.
// macOS surfaced it first only because a separate failure there emptied a
// different file; the same fixture reproduces it on Linux.
func TestPrivateFileWithNoScopedEntriesLoads(t *testing.T) {
	repo := newFixtureRepo(t)
	marker := "zq" + "unscoped" + "marker"
	patterns := writePrivatePatterns(t, marker)
	writeAndCommit(t, repo, "notes.txt", []byte("a line with "+marker+"\n"), "add notes")

	stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree")
	combined := stdout + stderr

	if strings.Contains(combined, "error") || strings.Contains(combined, "Illegal number") {
		t.Fatalf("the loader errored on a pattern file with no scoped entries\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if code != 1 {
		t.Fatalf("expected the unscoped pattern to be loaded and to catch notes.txt (exit 1), got exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(combined, "notes.txt") {
		t.Fatalf("expected the report to name notes.txt\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestPatternLoadFailureIsLoud pins the property that matters more than any
// individual check in this file: when the script cannot assemble the pattern
// set it was asked to scan with, it must say so and exit non-zero. It must
// never print a clean tree.
//
// A scan that reports success having checked nothing is worse than no scan,
// because it is trusted. Every hygiene bug this repo has hit has had that
// shape — the stderr blind spot, the dropped byte-range entry — so the
// behaviour is pinned directly rather than inferred from the checks above.
//
// An unreadable pattern file is the trigger here because it is deterministic;
// the guard is not specific to that cause and fires on any short load.
func TestPatternLoadFailureIsLoud(t *testing.T) {
	repo := newFixtureRepo(t)
	patterns := writePrivatePatterns(t, "zq"+"marker", "text:"+sampleScopedPattern())
	if err := os.Chmod(patterns, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(patterns, 0o600) })
	if f, err := os.Open(patterns); err == nil {
		f.Close()
		t.Skip("running as a user that ignores file modes (root); cannot make a file unreadable")
	}

	stdout, stderr, code := runHygieneCheckWith(t, repo, patterns, "--tree")
	combined := stdout + stderr

	if code == 0 {
		t.Fatalf("an unloadable pattern file exited 0 — a failed load must never pass quietly\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if strings.Contains(combined, "working tree clean") {
		t.Fatalf("an unloadable pattern file reported a clean tree\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(combined, "refusing to scan") {
		t.Fatalf("expected the refusal to say why\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// ---------------------------------------------------------------------------
// Embedded metadata.
//
// hygiene-check.sh reads the embedded metadata of every binary or media file
// a scan reaches with exiftool, and checks the fields it decodes against
// every pattern, whatever its scope.
// ---------------------------------------------------------------------------

// realExiftool returns the host's exiftool, or skips. These tests are about
// what the real reader decodes, which no stub can stand in for. CI installs
// exiftool in the lint-and-test job so that there they run rather than skip.
func realExiftool(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("exiftool")
	if err != nil {
		t.Skip("exiftool not installed")
	}
	return path
}

// pngWithCompressedXMP builds a 1x1 PNG whose XMP packet carries value in its
// xmp:CreatorTool field, stored the way PNG stores a compressed XMP packet: a
// zlib-compressed iTXt chunk under the keyword XML:com.adobe.xmp. The value is
// then nowhere in the file's bytes — checked below, not assumed — so the byte
// scan cannot find it, and a test that catches it has caught it through
// exiftool and nothing else.
func pngWithCompressedXMP(t *testing.T, value string) []byte {
	t.Helper()
	var img bytes.Buffer
	if err := png.Encode(&img, image.NewGray(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatalf("encode png: %v", err)
	}

	xmp := `<x:xmpmeta xmlns:x="adobe:ns:meta/">` +
		`<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">` +
		`<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">` +
		`<xmp:CreatorTool>` + value + `</xmp:CreatorTool>` +
		`</rdf:Description></rdf:RDF></x:xmpmeta>`
	var packed bytes.Buffer
	zw := zlib.NewWriter(&packed)
	if _, err := zw.Write([]byte(xmp)); err != nil {
		t.Fatalf("compress xmp: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("compress xmp: %v", err)
	}

	// Chunk type, then the iTXt fields: keyword and NUL, compression flag 1,
	// method 0 (zlib), an empty language tag and translated keyword (each
	// NUL-terminated), then the compressed text. The length counts the
	// fields only; the CRC covers the type and the fields.
	body := append([]byte("iTXt"), "XML:com.adobe.xmp"...)
	body = append(body, 0, 1, 0, 0, 0)
	body = append(body, packed.Bytes()...)
	chunk := binary.BigEndian.AppendUint32(nil, uint32(len(body)-4))
	chunk = append(chunk, body...)
	chunk = binary.BigEndian.AppendUint32(chunk, crc32.ChecksumIEEE(body))

	// Insert it before IEND, the last 12 bytes of the encoded image.
	raw := img.Bytes()
	iend := len(raw) - 12
	out := append(append(append([]byte{}, raw[:iend]...), chunk...), raw[iend:]...)

	if bytes.Contains(bytes.ToLower(out), bytes.ToLower([]byte(value))) {
		t.Fatal("fixture carries its metadata value in its raw bytes, so it cannot tell the metadata scan from the byte scan")
	}
	return out
}

// TestTreeCatchesPatternInCompressedImageMetadata is the case the metadata
// scan exists for: a banned value the byte scan cannot see, because the
// format compressed it.
func TestTreeCatchesPatternInCompressedImageMetadata(t *testing.T) {
	exiftool := realExiftool(t)
	repo := newFixtureRepo(t)
	writeAndCommit(t, repo, "shot.png", pngWithCompressedXMP(t, bannedMarker()+" 1.0"), "add image")

	stdout, stderr, code := runHygieneCheckExif(t, repo, exiftool, writePrivatePatterns(t, bannedMarker()), "--tree")
	combined := stdout + stderr

	if code != 1 {
		t.Fatalf("expected a banned value in compressed image metadata to be caught (exit 1), got exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(combined, "shot.png") || !strings.Contains(combined, "CreatorTool") {
		t.Fatalf("expected the report to name shot.png and the field the value sits in\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestMetaScopedPatternIsCheckedInMetadataOnly: a meta: entry catches its
// value in an image's embedded metadata, and leaves the same value alone in
// a tracked text file and in a commit message.
func TestMetaScopedPatternIsCheckedInMetadataOnly(t *testing.T) {
	exiftool := realExiftool(t)
	patterns := writePrivatePatterns(t, "meta:"+metaMarker())

	t.Run("in text and a commit message", func(t *testing.T) {
		repo := newFixtureRepo(t)
		writeAndCommit(t, repo, "notes.md", []byte("notes on "+metaMarker()+"\n"), "notes on "+metaMarker())
		for _, args := range [][]string{{"--tree"}, {"--range", "HEAD~1..HEAD"}} {
			stdout, stderr, code := runHygieneCheckExif(t, repo, exiftool, patterns, args...)
			if code != 0 {
				t.Fatalf("%v: expected a meta: entry to leave text alone, got exit %d\nstdout:\n%s\nstderr:\n%s", args, code, stdout, stderr)
			}
		}
	})
	t.Run("in image metadata", func(t *testing.T) {
		repo := newFixtureRepo(t)
		writeAndCommit(t, repo, "shot.png", pngWithCompressedXMP(t, metaMarker()+" 1.0"), "add image")
		for _, args := range [][]string{{"--tree"}, {"--range", "HEAD~1..HEAD"}} {
			stdout, stderr, code := runHygieneCheckExif(t, repo, exiftool, patterns, args...)
			if code != 1 || !strings.Contains(stdout+stderr, "shot.png") {
				t.Fatalf("%v: expected a meta: entry to catch shot.png's metadata (exit 1), got exit %d\nstdout:\n%s\nstderr:\n%s", args, code, stdout, stderr)
			}
		}
	})
}

// TestTreeCatchesScopedPatternInBinaryMetadata: a text-scoped pattern is
// skipped on a binary's raw bytes, where it would match compressed payload by
// coincidence, but is applied to the fields exiftool decodes, which carry no
// payload. The skip itself is pinned by TestTreeBinarySkipsScopedPatterns.
func TestTreeCatchesScopedPatternInBinaryMetadata(t *testing.T) {
	exiftool := realExiftool(t)
	repo := newFixtureRepo(t)
	patterns := writePrivatePatterns(t, "text:"+sampleScopedPattern())
	writeAndCommit(t, repo, "shot.gif", gifWithMetadata(sampleScopedText(), ""), "add image")

	stdout, stderr, code := runHygieneCheckExif(t, repo, exiftool, patterns, "--tree")
	combined := stdout + stderr

	if code != 1 {
		t.Fatalf("expected a text-scoped pattern in a GIF comment to be caught through its metadata (exit 1), got exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(combined, "shot.gif") || !strings.Contains(combined, "embedded metadata") {
		t.Fatalf("expected the report to name shot.gif and say the hit is in its embedded metadata\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestRangeReadsImageMetadataOutOfTheCommit covers the path that actually
// gates a push and a PR: a commit range, not the working tree. The image is
// added in one commit and deleted in the next, so it exists only in the
// commit that added it — the scan has to read it out of that commit's tree,
// and must not trip over the deletion.
func TestRangeReadsImageMetadataOutOfTheCommit(t *testing.T) {
	exiftool := realExiftool(t)
	repo := newFixtureRepo(t)
	writeAndCommit(t, repo, "docs/shot.png", pngWithCompressedXMP(t, bannedMarker()+" 1.0"), "add image")
	runGit(t, repo, "rm", "-q", "docs/shot.png")
	runGit(t, repo, "commit", "-q", "-m", "remove image")

	stdout, stderr, code := runHygieneCheckExif(t, repo, exiftool, writePrivatePatterns(t, bannedMarker()), "--range", "HEAD~2..HEAD")
	combined := stdout + stderr

	if code != 1 {
		t.Fatalf("expected the image's metadata to be read out of the commit that added it (exit 1), got exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(combined, "docs/shot.png") || !strings.Contains(combined, "CreatorTool") {
		t.Fatalf("expected the report to name docs/shot.png and the field the value sits in\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(combined, "scanned 2 commit(s), 1 with hits") {
		t.Fatalf("expected exactly the adding commit to be reported, and the deleting one to scan clean\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestCleanImageMetadataPasses is the control. Images whose metadata holds
// nothing banned, and a binary exiftool does not recognise at all, pass
// through both the tree and the range path — with every scope loaded, so
// nothing exiftool prints about an ordinary file is enough to fail it.
func TestCleanImageMetadataPasses(t *testing.T) {
	exiftool := realExiftool(t)
	repo := newFixtureRepo(t)
	patterns := writePrivatePatterns(t, bannedMarker(), "text:"+sampleScopedPattern(), "meta:"+metaMarker())
	writeAndCommit(t, repo, "shot.png", pngWithCompressedXMP(t, "ZqPaint 2.1"), "add image")
	writeAndCommit(t, repo, "loop.gif", gifWithMetadata("made by hand", ""), "add animation")
	writeAndCommit(t, repo, "asset.bin", []byte{0x00, 0x01, 0x02, 0xFF, 0x00}, "add binary asset")

	for _, args := range [][]string{{"--tree"}, {"--range", "HEAD~3..HEAD"}} {
		stdout, stderr, code := runHygieneCheckExif(t, repo, exiftool, patterns, args...)
		if code != 0 {
			t.Fatalf("%v: expected clean images to pass, got exit %d\nstdout:\n%s\nstderr:\n%s", args, code, stdout, stderr)
		}
	}
}

// assertUnscanned checks that a run refused to pass a file whose embedded
// metadata went unread: configuration-error status, the file named, and no
// clean report anywhere in the output.
func assertUnscanned(t *testing.T, code int, stdout, stderr, file string) {
	t.Helper()
	combined := stdout + stderr
	if code != 2 {
		t.Fatalf("expected exit 2 for a file whose metadata went unread, got exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(combined, file) || !strings.Contains(combined, "NOT scanned") {
		t.Fatalf("expected the report to name %s as not scanned\nstdout:\n%s\nstderr:\n%s", file, stdout, stderr)
	}
	if strings.Contains(combined, "working tree clean") {
		t.Fatalf("a run with an unread file reported a clean tree\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// TestMissingExiftoolFailsClosed: without a metadata reader, a file that
// needs one must fail the scan, never pass it — a check that quietly did not
// run reports clean on exactly what it exists to catch. That covers a text
// file with a document extension too, which git does not call binary. A range
// with no such file needs no reader, and must not be blocked for lacking one.
func TestMissingExiftoolFailsClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-exiftool")
	patterns := writePrivatePatterns(t, bannedMarker())
	textPDF := []byte("%PDF-1.4\n% an uncompressed, text-only PDF\n")

	t.Run("tree with a binary", func(t *testing.T) {
		repo := newFixtureRepo(t)
		writeAndCommit(t, repo, "asset.bin", []byte{0x00, 0x01, 0xFF, 0x00}, "add binary asset")
		stdout, stderr, code := runHygieneCheckExif(t, repo, missing, patterns, "--tree")
		assertUnscanned(t, code, stdout, stderr, "asset.bin")
	})
	t.Run("tree with a text PDF", func(t *testing.T) {
		repo := newFixtureRepo(t)
		writeAndCommit(t, repo, "spec.pdf", textPDF, "add document")
		stdout, stderr, code := runHygieneCheckExif(t, repo, missing, patterns, "--tree")
		assertUnscanned(t, code, stdout, stderr, "spec.pdf")
	})
	t.Run("range with an image", func(t *testing.T) {
		repo := newFixtureRepo(t)
		writeAndCommit(t, repo, "shot.png", pngWithCompressedXMP(t, "ZqPaint 2.1"), "add image")
		stdout, stderr, code := runHygieneCheckExif(t, repo, missing, patterns, "--range", "HEAD~1..HEAD")
		assertUnscanned(t, code, stdout, stderr, "shot.png")
	})
	t.Run("range with a text PDF", func(t *testing.T) {
		repo := newFixtureRepo(t)
		writeAndCommit(t, repo, "spec.pdf", textPDF, "add document")
		stdout, stderr, code := runHygieneCheckExif(t, repo, missing, patterns, "--range", "HEAD~1..HEAD")
		assertUnscanned(t, code, stdout, stderr, "spec.pdf")
	})
	t.Run("range with no binary", func(t *testing.T) {
		repo := newFixtureRepo(t)
		writeAndCommit(t, repo, "notes.txt", []byte("plain text\n"), "add notes")
		stdout, stderr, code := runHygieneCheckExif(t, repo, missing, patterns, "--range", "HEAD~1..HEAD")
		if code != 0 {
			t.Fatalf("a text-only range was blocked for want of exiftool, got exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
	})
}

// TestExiftoolThatReadsNothingFailsClosed: an exiftool that runs but never
// reports reading the file is treated like a missing one. This stand-in
// answers the way the real one answers a file it could not open — nothing on
// stdout, exit 1. The exit status is no guide on its own: the real exiftool
// also exits 1 for a file it read and did not recognise.
func TestExiftoolThatReadsNothingFailsClosed(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "exiftool")
	body := "#!/bin/sh\necho 'Error: File not found' >&2\nexit 1\n"
	if err := os.WriteFile(broken, []byte(body), 0o755); err != nil {
		t.Fatalf("write broken exiftool: %v", err)
	}
	repo := newFixtureRepo(t)
	writeAndCommit(t, repo, "asset.bin", []byte{0x00, 0x01, 0xFF, 0x00}, "add binary asset")

	stdout, stderr, code := runHygieneCheckExif(t, repo, broken, writePrivatePatterns(t, bannedMarker()), "--tree")
	assertUnscanned(t, code, stdout, stderr, "asset.bin")
}
