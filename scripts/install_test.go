// Package scripts_test drives the real installer scripts against a fake
// GitHub release and proves that they refuse to install a binary they cannot
// verify.
//
// Everything here runs the scripts as shipped — scripts/install through
// /bin/sh, scripts/install.ps1 through PowerShell — with no copying, no
// rewriting, and no test-only code path inside either script. The only
// concessions the scripts make to being tested are two environment variables
// that move the download host (CONSTLE_INSTALL_BASE_URL and
// CONSTLE_INSTALL_API_URL, both restricted to HTTPS or loopback) and
// CONSTLE_INSTALL_DIR, which already existed.
//
// Two things make these regression tests rather than smoke tests:
//
//   - Every refusal case asserts three things together: a non-zero exit, a
//     specific message, and an install directory that is still empty. Any one
//     of the three alone can pass for the wrong reason.
//   - Each case names, in its comment, the deletion it catches. If removing a
//     line from a script does not turn some test red, that test is decoration.
package scripts_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// The installers' own spellings, defined once. A rename on either side breaks
// compilation here rather than silently leaving every test pointed at the real
// github.com — which would turn this whole file green and meaningless.
const (
	envBaseURL       = "CONSTLE_INSTALL_BASE_URL"
	envAPIURL        = "CONSTLE_INSTALL_API_URL"
	envInstallDir    = "CONSTLE_INSTALL_DIR"
	envRequireSig    = "CONSTLE_REQUIRE_SIGNATURE"
	envAllowUnsigned = "CONSTLE_ALLOW_UNSIGNED"
	envVersion       = "CONSTLE_VERSION"

	// Must match the shell's v[0-9]* glob, or scripts/install treats it as a
	// commit sha and builds from source instead of downloading anything.
	testTag     = "v9.9.9"
	testVersion = "9.9.9"
)

// A raw string literal: in an interpreted literal `\.` is an invalid escape.
// These are compared byte-for-byte against both scripts and the README.
const identityRegexp = `^https://github\.com/constle/constle/\.github/workflows/release\.yaml@refs/tags/v`

const oidcIssuer = "https://token.actions.githubusercontent.com"

// Sentinel bytes for the payload inside each archive, so a test can tell
// "the real binary was installed" from "something was installed".
const (
	goodPayload    = "#!/bin/sh\necho constle-genuine\n"
	tamperedMarker = "constle-TAMPERED-PAYLOAD"
)

// ---------------------------------------------------------------------------
// The cosign stub
//
// cosign is not installed on CI runners and cannot be exercised for real
// anyway: a genuine keyless verification needs a Fulcio certificate minted
// from a GitHub OIDC token. So the tests put a stub named cosign on PATH.
//
// The stub is this test binary re-executing itself. A .cmd/.bat shim is not
// an option: cmd.exe's caret handling eats the leading ^ of the identity
// regexp, so an argv assertion built on one would pass against an unanchored,
// materially weaker pin — worse than no assertion at all. A #!/bin/sh shim is
// not found by PowerShell's Get-Command on Windows. Re-executing the test
// binary is byte-faithful on both, and needs no compiler at test time.
// ---------------------------------------------------------------------------
const (
	stubEnv     = "CONSTLE_TEST_COSIGN_STUB"
	stubArgvEnv = "CONSTLE_TEST_COSIGN_ARGV"
	stubExitEnv = "CONSTLE_TEST_COSIGN_EXIT"
	stubSayEnv  = "CONSTLE_TEST_COSIGN_SAY"
)

var cosignStubDir string

func TestMain(m *testing.M) {
	if os.Getenv(stubEnv) != "" {
		cosignStubMain()
		return
	}

	// os.MkdirTemp rather than a t.TempDir behind a sync.Once: a t.TempDir
	// belongs to whichever test created it and is removed when that test
	// finishes, so later tests would have a PATH entry pointing at a deleted
	// stub, quietly take the cosign-absent branch, and pass at random.
	dir, err := os.MkdirTemp("", "constle-cosign-stub")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	cosignStubDir = dir
	if err := installStub(dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// cosignStubMain is what runs when this binary is invoked under the name
// "cosign". It records its arguments and exits with whatever status the test
// asked for.
func cosignStubMain() {
	if p := os.Getenv(stubArgvEnv); p != "" {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			os.Exit(2)
		}
		for _, a := range os.Args[1:] {
			_, _ = fmt.Fprintln(f, a)
		}
		// Record the digest of the file cosign was pointed at. Argv adjacency
		// proves the flags were passed; this proves the signature was checked
		// over the same bytes the checksum comparison later trusts. An
		// installer that verified a stale or second copy of checksums.txt
		// would satisfy every other assertion in the suite.
		if n := len(os.Args); n > 1 {
			if b, err := os.ReadFile(os.Args[n-1]); err == nil {
				_, _ = fmt.Fprintf(f, "BLOBSHA=%x\n", sha256.Sum256(b))
			}
		}
		_ = f.Close()
	}

	// Output and exit status are set independently. Welding them together
	// (exit 0 always prints "Verified OK") would make "branch on the exit
	// status, never on the output" a comment no test could enforce.
	if say := os.Getenv(stubSayEnv); say != "" {
		_, _ = fmt.Fprintln(os.Stderr, say)
	}
	if os.Getenv(stubExitEnv) == "1" {
		os.Exit(1)
	}
}

func installStub(dir string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	name := "cosign"
	if runtime.GOOS == "windows" {
		name = "cosign.exe"
	}
	dst := filepath.Join(dir, name)

	if runtime.GOOS != "windows" {
		if err := os.Symlink(self, dst); err == nil {
			return nil
		}
		// Fall through to copying: /tmp and the test binary may be on
		// filesystems that refuse symlinks.
	}
	b, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

// ---------------------------------------------------------------------------
// Fixtures: a release built in memory, byte-identical in shape to a real one
// ---------------------------------------------------------------------------

type fixtures struct {
	// assets is what the fake release serves, keyed by filename. Deleting a
	// key makes that asset 404.
	assets map[string][]byte
	// shArchive and psArchive name the asset each installer will ask for,
	// given the uname shim and PROCESSOR_ARCHITECTURE the tests set.
	shArchive string
	psArchive string
}

func buildFixtures(t *testing.T) *fixtures {
	t.Helper()

	f := &fixtures{
		assets:    map[string][]byte{},
		shArchive: "constle_" + testVersion + "_linux_amd64.tar.gz",
		psArchive: "constle_" + testVersion + "_windows_amd64.zip",
	}

	for _, osName := range []string{"linux", "darwin"} {
		for _, arch := range []string{"amd64", "arm64"} {
			name := fmt.Sprintf("constle_%s_%s_%s.tar.gz", testVersion, osName, arch)
			f.assets[name] = makeTarGz(t, "constle", goodPayload)
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		name := fmt.Sprintf("constle_%s_windows_%s.zip", testVersion, arch)
		f.assets[name] = makeZip(t, "constle.exe", goodPayload)
	}

	f.assets["checksums.txt"] = []byte(checksumsFor(f.assets))
	// The stub never parses these, so their contents are arbitrary — but they
	// must exist for the signature path to be reached at all.
	f.assets["checksums.txt.sig"] = []byte("fake-signature\n")
	f.assets["checksums.txt.pem"] = []byte("fake-certificate\n")
	return f
}

// checksumsFor renders a checksums.txt in GoReleaser's exact byte layout:
// lowercase hex, exactly two spaces, the bare basename, LF endings. Verified
// by hexdumping the real checksums.txt from release v0.5.0.
func checksumsFor(assets map[string][]byte) string {
	names := make([]string, 0, len(assets))
	for name := range assets {
		if strings.HasPrefix(name, "checksums.txt") {
			continue // checksums.txt does not list itself
		}
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "%x  %s\n", sha256.Sum256(assets[name]), name)
	}
	return b.String()
}

func makeTarGz(t *testing.T, binaryName, payload string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	// A real GoReleaser archive is flat: LICENSE, README.md and the binary,
	// all at the root, no wrapping directory.
	write := func(name, body string, mode int64) {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar body %s: %v", name, err)
		}
	}
	write("LICENSE", "license text\n", 0o644)
	write("README.md", "readme text\n", 0o644)
	write(binaryName, payload, 0o755)

	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func makeZip(t *testing.T, binaryName, payload string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []struct{ name, body string }{
		{"LICENSE", "license text\n"},
		{"README.md", "readme text\n"},
		{binaryName, payload},
	} {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("zip create %s: %v", e.name, err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatalf("zip write %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// The fake GitHub
// ---------------------------------------------------------------------------

type fakeGitHub struct {
	*httptest.Server
	mu   sync.Mutex
	hits []string
	fx   *fixtures
	tag  string
}

func newFakeGitHub(t *testing.T, fx *fixtures) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{fx: fx, tag: testTag}

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/constle/constle/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		g.record(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		// The space after the colon is required: scripts/install parses this
		// with sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'.
		_, _ = fmt.Fprintf(w, `{"tag_name": %q, "name": "Release %s"}`, g.tag, g.tag)
	})

	prefix := "/constle/constle/releases/download/"
	mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
		g.record(r.URL.Path)
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 || parts[0] != g.tag {
			http.NotFound(w, r)
			return
		}
		body, ok := g.fx.assets[parts[1]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})

	g.Server = httptest.NewServer(mux)
	t.Cleanup(g.Close)
	return g
}

func (g *fakeGitHub) record(path string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.hits = append(g.hits, path)
}

func (g *fakeGitHub) hitLog() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.hits...)
}

// requested reports whether any request asked for the named release asset.
func (g *fakeGitHub) requested(asset string) bool {
	for _, h := range g.hitLog() {
		if strings.HasSuffix(h, "/"+asset) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Running the installers
// ---------------------------------------------------------------------------

func skipIfWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skipf("scripts/install is a POSIX sh script and refuses to run on %s", runtime.GOOS)
	}
}

func repoFile(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(name)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("stat %s: %v", abs, err)
	}
	return abs
}

// fakeBin builds a PATH directory holding only the tools named, symlinked
// from the host. The installers then run against a known toolset rather than
// whatever the developer happens to have.
//
// This is not hygiene. A developer with ~/go/bin on PATH has a real cosign
// there, and the cosign-absent cases would quietly attempt a genuine Sigstore
// verification against a fake signature.
func fakeBin(t *testing.T, tools ...string) string {
	t.Helper()
	skipIfWindows(t)

	dir := t.TempDir()
	for _, tool := range tools {
		src, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("required tool %q not found on this host: %v", tool, err)
		}
		if err := os.Symlink(src, filepath.Join(dir, tool)); err != nil {
			t.Fatalf("symlink %s: %v", tool, err)
		}
	}
	return dir
}

// baseTools is everything scripts/install invokes as an external command,
// minus the digest backends, which individual tests control.
//
// gzip is not obvious and is load-bearing: tar -xzf shells out to it, and
// without it the run dies with "gzip: Cannot exec" long before anything
// interesting happens.
var baseTools = []string{
	"uname", "curl", "mktemp", "tar", "gzip", "head",
	"chmod", "mv", "rm", "mkdir", "grep", "sed", "awk", "tr",
}

// unameShim writes a uname replacement reporting a fixed system and machine,
// so the archive name the installer asks for does not depend on the host.
func unameShim(t *testing.T, dir, system, machine string) {
	t.Helper()
	writeShim(t, dir, "uname",
		fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\n  -s) echo %s ;;\n  -m) echo %s ;;\nesac\n", system, machine))
}

// writeShim installs a small shell script into a fakeBin directory, replacing
// any symlink already there. The removal is not optional: writing over a
// symlink follows it, so without this the test would try to overwrite
// /usr/bin/uname on the host.
func writeShim(t *testing.T, dir, name, script string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatalf("replace %s shim: %v", name, err)
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write %s shim: %v", name, err)
	}
}

type runOpts struct {
	binDir string // PATH for the child; defaults to base tools + sha256sum
	// The cosign stub is on PATH by default, because an install that cannot
	// run cosign now refuses. Opting OUT is what a test does when the absence
	// of cosign is the thing under test; leaving this false in a new test can
	// no longer make it pass by silently exercising the refusal path instead.
	withoutCosign bool
	argvLog       string            // where the stub records its arguments
	env           map[string]string // extra or overriding variables
	installDir    string            // filled in by run, for assertions
}

type result struct {
	exit       int
	stdout     string
	stderr     string
	installDir string
}

// out is what assertions match against. Both scripts write some failure text
// to stdout and some to stderr — PowerShell's Write-Host goes to stdout even
// for errors — so tests assert on the combination rather than guessing.
func (r result) out() string { return r.stdout + r.stderr }

func run(t *testing.T, g *fakeGitHub, argv []string, o *runOpts) result {
	t.Helper()

	installDir := filepath.Join(t.TempDir(), "bin")
	// scripts/install tests [ -w "$INSTALL_DIR" ], which is false for a
	// directory that does not exist, and would send the run down the sudo
	// branch instead of the one under test.
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatalf("mkdir install dir: %v", err)
	}
	o.installDir = installDir

	path := o.binDir
	stubMarker := ""
	if !o.withoutCosign {
		path = path + string(os.PathListSeparator) + cosignStubDir
		// Without this the stub binary — which is this test binary — would
		// start as an ordinary test binary and run the entire suite again,
		// recursively, until the context deadline.
		stubMarker = "1"
	}

	tmp := t.TempDir()
	env := map[string]string{
		"PATH":        path,
		"HOME":        t.TempDir(),
		"TMPDIR":      tmp,
		envInstallDir: installDir,
		envBaseURL:    g.URL,
		envAPIURL:     g.URL,
		stubEnv:       stubMarker,
		stubArgvEnv:   o.argvLog,
	}
	// Windows needs a handful of variables that a POSIX child does not, and
	// leaving them out fails in a way that looks like the script's fault. In
	// particular PATHEXT is what makes PowerShell's Get-Command resolve the
	// bare name "cosign" to the stub's cosign.exe; without it the signature
	// branch silently takes the cosign-is-not-installed path and the cosign
	// cases pass an installer that never called cosign at all.
	if runtime.GOOS == "windows" {
		env["PATHEXT"] = ".COM;.EXE;.BAT;.CMD"
		env["TEMP"] = tmp
		env["TMP"] = tmp
		for _, name := range []string{"SystemRoot", "windir", "COMSPEC", "USERPROFILE"} {
			if v := os.Getenv(name); v != "" {
				env[name] = v
			}
		}
	}

	for k, v := range o.env {
		env[k] = v
	}

	// A fully explicit environment, never append(os.Environ(), ...): an
	// inherited PATH or COSIGN_* would decide the outcome of half these tests.
	envSlice := make([]string, 0, len(env))
	for k, v := range env {
		if v == "" {
			continue
		}
		envSlice = append(envSlice, k+"="+v)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = envSlice
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := result{stdout: stdout.String(), stderr: stderr.String(), installDir: installDir}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		res.exit = 0
	case errors.As(err, &exitErr):
		res.exit = exitErr.ExitCode()
	default:
		t.Fatalf("running %v: %v\n%s", argv, err, res.out())
	}
	return res
}

// runSh runs scripts/install through /bin/sh.
func runSh(t *testing.T, g *fakeGitHub, o *runOpts) result {
	t.Helper()
	skipIfWindows(t)
	if o.binDir == "" {
		dir := fakeBin(t, append(baseTools, "sha256sum")...)
		unameShim(t, dir, "Linux", "x86_64")
		o.binDir = dir
	}
	return run(t, g, []string{"/bin/sh", repoFile(t, "install")}, o)
}

// powerShell finds an interpreter for scripts/install.ps1.
//
// On Windows, failing to find one is fatal rather than a skip: a runner-image
// change must not be allowed to turn the entire PowerShell half of this suite
// into a permanent green no-op, which is exactly the failure it exists to
// prevent. Elsewhere PowerShell is genuinely optional and the tests skip.
func powerShell(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"pwsh", "powershell"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	if runtime.GOOS == "windows" {
		t.Fatal("neither pwsh nor powershell is on PATH; scripts/install.ps1 cannot be tested on its own platform")
	}
	t.Skip("no pwsh or powershell on PATH; skipping the scripts/install.ps1 cases")
	return ""
}

func runPs1(t *testing.T, g *fakeGitHub, o *runOpts) result {
	t.Helper()
	ps := powerShell(t)

	if o.binDir == "" {
		// PowerShell needs no external tools of its own; the directory exists
		// only so that PATH is a known quantity and cosign can be added to it.
		o.binDir = t.TempDir()
	}
	if o.env == nil {
		o.env = map[string]string{}
	}
	// The script reads this to pick the archive; on a non-Windows host it is
	// unset and the script would correctly refuse.
	if _, ok := o.env["PROCESSOR_ARCHITECTURE"]; !ok {
		o.env["PROCESSOR_ARCHITECTURE"] = "AMD64"
	}

	// -NoProfile matters: a profile could define a cosign function that
	// defeats the stub, or reset $ErrorActionPreference.
	argv := []string{ps, "-NoProfile", "-NonInteractive", "-File", repoFile(t, "install.ps1")}
	return run(t, g, argv, o)
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

// assertRefused is the shared triple. All three parts are needed: a non-zero
// exit alone is satisfied by the script failing for an unrelated reason, and
// a matching message alone does not prove nothing was installed.
func assertRefused(t *testing.T, res result, marker string) {
	t.Helper()
	if res.exit == 0 {
		t.Errorf("exit code = 0, want non-zero (the installer accepted it)\n%s", res.out())
	}
	if !strings.Contains(res.out(), marker) {
		t.Errorf("output does not contain %q\n%s", marker, res.out())
	}
	assertNothingInstalled(t, res)
}

func assertNothingInstalled(t *testing.T, res result) {
	t.Helper()
	entries, err := os.ReadDir(res.installDir)
	if err != nil {
		t.Fatalf("read install dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("install directory is not empty: %v\n%s", names, res.out())
	}
}

// assertNotExtracted proves the ordering: verification happened before the
// archive was unpacked. Both scripts print this line immediately before
// extracting and nowhere else, which makes it a better witness than a tar or
// zip error — those are localized, and the zip one comes from .NET.
func assertNotExtracted(t *testing.T, res result) {
	t.Helper()
	if strings.Contains(res.out(), "extracting...") {
		t.Errorf("the archive was extracted before verification refused it\n%s", res.out())
	}
}

func assertInstalled(t *testing.T, res result, binary string) {
	t.Helper()
	if res.exit != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", res.exit, res.out())
	}
	b, err := os.ReadFile(filepath.Join(res.installDir, binary))
	if err != nil {
		t.Fatalf("installed binary: %v\n%s", err, res.out())
	}
	if string(b) != goodPayload {
		t.Errorf("installed bytes are not the archive payload: %q", string(b))
	}
}

// ---------------------------------------------------------------------------
// The happy paths — negative controls
//
// Without these, every refusal test could be satisfied by a script that
// always fails.
// ---------------------------------------------------------------------------

func TestShInstallsPinnedRelease(t *testing.T) {
	t.Parallel()
	fx := buildFixtures(t)
	g := newFakeGitHub(t, fx)
	argv := filepath.Join(t.TempDir(), "argv.log")

	res := runSh(t, g, &runOpts{
		argvLog: argv,
		env:     map[string]string{envVersion: testTag},
	})

	assertInstalled(t, res, "constle")
	if !strings.Contains(res.out(), "checksum and signature verified") {
		t.Errorf("success line does not state what was verified\n%s", res.out())
	}
	// With a pinned tag the API is never consulted: REF takes the v[0-9]*
	// branch straight to the download.
	for _, h := range g.hitLog() {
		if strings.Contains(h, "/releases/latest") {
			t.Errorf("a pinned tag should not call the releases API, but did: %v", g.hitLog())
		}
	}
	for _, asset := range []string{fx.shArchive, "checksums.txt", "checksums.txt.sig", "checksums.txt.pem"} {
		if !g.requested(asset) {
			t.Errorf("installer never fetched %s (hits: %v)", asset, g.hitLog())
		}
	}
}

// The default path, which is what the documented one-liner does.
func TestShInstallsLatestRelease(t *testing.T) {
	t.Parallel()
	fx := buildFixtures(t)
	g := newFakeGitHub(t, fx)

	res := runSh(t, g, &runOpts{})
	assertInstalled(t, res, "constle")

	if len(g.hitLog()) == 0 || !strings.Contains(g.hitLog()[0], "/releases/latest") {
		t.Errorf("first request was not the releases API: %v", g.hitLog())
	}
}

func TestPs1InstallsLatestRelease(t *testing.T) {
	t.Parallel()
	fx := buildFixtures(t)
	g := newFakeGitHub(t, fx)

	res := runPs1(t, g, &runOpts{})
	assertInstalled(t, res, "constle.exe")
	if !strings.Contains(res.out(), "checksum verified") {
		t.Errorf("success path never reported a verified checksum\n%s", res.out())
	}
}

// ---------------------------------------------------------------------------
// Tampering
// ---------------------------------------------------------------------------

// CATCHES: deletion of the archive-digest comparison in either script.
func TestTamperedArchiveIsRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		runner func(*testing.T, *fakeGitHub, *runOpts) result
		asset  func(*fixtures) string
	}{
		{"sh", runSh, func(f *fixtures) string { return f.shArchive }},
		{"ps1", runPs1, func(f *fixtures) string { return f.psArchive }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := buildFixtures(t)
			// checksums.txt still lists the genuine digest.
			fx.assets[tc.asset(fx)] = []byte("not an archive at all, just bytes")
			g := newFakeGitHub(t, fx)

			res := tc.runner(t, g, &runOpts{})
			assertRefused(t, res, "CHECKSUM MISMATCH")
			assertNotExtracted(t, res)
		})
	}
}

// The same attack with a WELL-FORMED archive, which is the case that proves
// the ordering rather than relying on the archive being unreadable.
//
// CATCHES: verification moved to after the archive is unpacked but before the
// binary is moved into place. That is the most likely accidental reordering,
// it is still a real vulnerability because tar and Expand-Archive parse
// attacker-controlled bytes, and TestTamperedArchiveIsRefused does not catch
// it — that test's archive is invalid, so extraction would fail anyway.
func TestTamperedButValidArchiveIsRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		runner func(*testing.T, *fakeGitHub, *runOpts) result
		build  func(*testing.T, *fixtures) string
	}{
		{"sh", runSh, func(t *testing.T, f *fixtures) string {
			f.assets[f.shArchive] = makeTarGz(t, "constle", tamperedMarker)
			return f.shArchive
		}},
		{"ps1", runPs1, func(t *testing.T, f *fixtures) string {
			f.assets[f.psArchive] = makeZip(t, "constle.exe", tamperedMarker)
			return f.psArchive
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := buildFixtures(t)
			good := checksumsFor(fx.assets) // digests of the genuine archives
			tc.build(t, fx)
			fx.assets["checksums.txt"] = []byte(good)
			g := newFakeGitHub(t, fx)

			res := tc.runner(t, g, &runOpts{})
			assertRefused(t, res, "CHECKSUM MISMATCH")
			assertNotExtracted(t, res)

			// And the payload must not have landed anywhere under the
			// install directory.
			err := filepath.WalkDir(res.installDir, func(p string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				b, readErr := os.ReadFile(p)
				if readErr == nil && bytes.Contains(b, []byte(tamperedMarker)) {
					t.Errorf("the tampered payload was written to %s", p)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("walk install dir: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The checksums.txt parser, driven from one table across both installers
//
// scripts/install uses awk (NF == 2 && $2 == want) and scripts/install.ps1
// uses -split plus -ceq. They are two implementations of one rule, so they
// are tested from the same table — which is how a divergence between them
// shows up as a failure rather than as a surprise years later.
// ---------------------------------------------------------------------------

var checksumCases = []struct {
	name string
	// body rewrites checksums.txt, given the genuine one and the archive name
	// the installer under test will look for.
	body        func(genuine, archive string, digest string) string
	wantMarker  string
	wantInstall bool
}{
	{
		// CATCHES: an absent entry being treated as "nothing to verify".
		// Also the anti-rollback control: an older release's genuinely signed
		// checksums.txt has no line for this version's filename.
		name: "entry_missing",
		body: func(genuine, archive, digest string) string {
			var keep []string
			for _, line := range strings.Split(strings.TrimRight(genuine, "\n"), "\n") {
				if !strings.HasSuffix(line, "  "+archive) {
					keep = append(keep, line)
				}
			}
			return strings.Join(keep, "\n") + "\n"
		},
		wantMarker: "no single entry",
	},
	{
		// CATCHES: replacing "exactly one match" with head -1 or a
		// first-match loop, which would let a prepended attacker line win.
		name: "duplicate_entry",
		body: func(genuine, archive, digest string) string {
			return strings.Repeat("0", 64) + "  " + archive + "\n" + genuine
		},
		wantMarker: "no single entry",
	},
	{
		// CATCHES: swapping exact field equality for a substring search
		// (grep -F, -like, or -match, where "." matches any character).
		name: "decoy_names_only",
		body: func(genuine, archive, digest string) string {
			z := strings.Repeat("0", 64)
			return z + "  " + archive + ".sig\n" +
				z + "  x" + archive + "\n" +
				z + "  " + strings.ReplaceAll(archive, ".", "X") + "\n"
		},
		wantMarker: "no single entry",
	},
	{
		// CATCHES: awk and PowerShell disagreeing about a trailing field.
		// They did, measurably, before NF == 2 was added.
		name: "three_fields",
		body: func(genuine, archive, digest string) string {
			return digest + "  " + archive + " extra\n"
		},
		wantMarker: "no single entry",
	},
	{
		// CATCHES: the length guard. 63 hex characters is not a digest.
		name: "short_digest",
		body: func(genuine, archive, digest string) string {
			return digest[:63] + "  " + archive + "\n"
		},
		wantMarker: "no single entry",
	},
	{
		// CATCHES: the charset guard.
		name: "non_hex_digest",
		body: func(genuine, archive, digest string) string {
			return "z" + digest[1:] + "  " + archive + "\n"
		},
		wantMarker: "no single entry",
	},
	{
		// A hash with no filename at all: the empty-expected path, which is
		// precisely what the is_sha256 guard exists for.
		name: "hash_only_line",
		body: func(genuine, archive, digest string) string {
			return digest + "\n"
		},
		wantMarker: "no single entry",
	},
	{
		// CRLF must still work. A later cleanup dropping tr -d '\r' would
		// otherwise fail closed for anyone behind a rewriting proxy.
		name: "crlf_line_endings",
		body: func(genuine, archive, digest string) string {
			return strings.ReplaceAll(genuine, "\n", "\r\n")
		},
		wantInstall: true,
	},
	{
		// Uppercase hex must still match: Get-FileHash returns uppercase and
		// checksums.txt is lowercase, so the comparison has to be
		// case-insensitive on both sides.
		name: "uppercase_hex",
		body: func(genuine, archive, digest string) string {
			return strings.ToUpper(digest) + "  " + archive + "\n"
		},
		wantInstall: true,
	},
}

func TestChecksumsParsing(t *testing.T) {
	t.Parallel()
	for _, runner := range []struct {
		name    string
		run     func(*testing.T, *fakeGitHub, *runOpts) result
		archive func(*fixtures) string
		binary  string
	}{
		{"sh", runSh, func(f *fixtures) string { return f.shArchive }, "constle"},
		{"ps1", runPs1, func(f *fixtures) string { return f.psArchive }, "constle.exe"},
	} {
		t.Run(runner.name, func(t *testing.T) {
			for _, tc := range checksumCases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					fx := buildFixtures(t)
					archive := runner.archive(fx)
					digest := fmt.Sprintf("%x", sha256.Sum256(fx.assets[archive]))
					fx.assets["checksums.txt"] = []byte(tc.body(checksumsFor(fx.assets), archive, digest))

					g := newFakeGitHub(t, fx)
					res := runner.run(t, g, &runOpts{})

					if tc.wantInstall {
						assertInstalled(t, res, runner.binary)
						return
					}
					assertRefused(t, res, tc.wantMarker)
					assertNotExtracted(t, res)
				})
			}
		})
	}
}

// CATCHES: any "checksums.txt could not be fetched, carry on anyway" branch.
func TestMissingChecksumsFileIsRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		run  func(*testing.T, *fakeGitHub, *runOpts) result
	}{{"sh", runSh}, {"ps1", runPs1}} {
		t.Run(tc.name, func(t *testing.T) {
			fx := buildFixtures(t)
			delete(fx.assets, "checksums.txt")
			g := newFakeGitHub(t, fx)

			res := tc.run(t, g, &runOpts{})
			assertRefused(t, res, "checksums.txt")
			assertNotExtracted(t, res)
		})
	}
}

// ---------------------------------------------------------------------------
// The signature
// ---------------------------------------------------------------------------

// CATCHES: any version where a cosign failure warns and carries on. This is
// the single most important case in the file: the archive and checksums.txt
// are both genuine and match each other, so the checksum alone would pass.
// Only the signature can refuse this install.
func TestCosignFailureIsRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		run  func(*testing.T, *fakeGitHub, *runOpts) result
	}{{"sh", runSh}, {"ps1", runPs1}} {
		t.Run(tc.name, func(t *testing.T) {
			fx := buildFixtures(t)
			g := newFakeGitHub(t, fx)

			res := tc.run(t, g, &runOpts{
				argvLog: filepath.Join(t.TempDir(), "argv.log"),
				env:     map[string]string{stubExitEnv: "1"},
			})
			assertRefused(t, res, "SIGNATURE VERIFICATION FAILED")
			assertNotExtracted(t, res)
		})
	}
}

// CATCHES: an implementation that reads cosign's output instead of branching
// on its exit status. cosign's output is derived from a certificate the
// attacker supplied, so "Verified OK" on a failing run is the realistic
// attack shape — not a hypothetical one.
func TestCosignExitStatusBeatsItsOutput(t *testing.T) {
	t.Parallel()
	for _, runner := range []struct {
		name string
		run  func(*testing.T, *fakeGitHub, *runOpts) result
		bin  string
	}{{"sh", runSh, "constle"}, {"ps1", runPs1, "constle.exe"}} {
		t.Run(runner.name, func(t *testing.T) {
			t.Run("says_ok_but_fails", func(t *testing.T) {
				fx := buildFixtures(t)
				g := newFakeGitHub(t, fx)
				res := runner.run(t, g, &runOpts{
					argvLog: filepath.Join(t.TempDir(), "argv.log"),
					env: map[string]string{
						stubExitEnv: "1",
						stubSayEnv:  "Verified OK",
					},
				})
				assertRefused(t, res, "SIGNATURE VERIFICATION FAILED")
			})

			t.Run("complains_but_succeeds", func(t *testing.T) {
				fx := buildFixtures(t)
				g := newFakeGitHub(t, fx)
				res := runner.run(t, g, &runOpts{
					argvLog: filepath.Join(t.TempDir(), "argv.log"),
					env: map[string]string{
						stubSayEnv: "error: no matching signatures found",
					},
				})
				assertInstalled(t, res, runner.bin)
			})
		})
	}
}

// CATCHES: dropping either --certificate-* flag, loosening the regexp
// (removing the ^, unescaping a dot), switching to a --flag=value spelling,
// appending --insecure-ignore-tlog, or verifying a different file than the
// one whose contents are then trusted.
//
// README.md says these two flags are "not optional". This is the test that
// makes that sentence true.
func TestCosignIsCalledWithThePinnedIdentity(t *testing.T) {
	t.Parallel()
	for _, runner := range []struct {
		name string
		run  func(*testing.T, *fakeGitHub, *runOpts) result
	}{{"sh", runSh}, {"ps1", runPs1}} {
		t.Run(runner.name, func(t *testing.T) {
			fx := buildFixtures(t)
			g := newFakeGitHub(t, fx)
			argv := filepath.Join(t.TempDir(), "argv.log")

			res := runner.run(t, g, &runOpts{argvLog: argv})
			if res.exit != 0 {
				t.Fatalf("exit = %d, want 0\n%s", res.exit, res.out())
			}

			raw, err := os.ReadFile(argv)
			if err != nil {
				t.Fatalf("cosign was never invoked: %v\n%s", err, res.out())
			}
			lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")

			var blobSHA string
			var args []string
			for _, l := range lines {
				if strings.HasPrefix(l, "BLOBSHA=") {
					blobSHA = strings.TrimPrefix(l, "BLOBSHA=")
					continue
				}
				args = append(args, l)
			}

			if len(args) == 0 || args[0] != "verify-blob" {
				t.Fatalf("cosign argv does not start with verify-blob: %v", args)
			}

			// Adjacency, not mere presence: "--certificate-identity-regexp"
			// appearing somewhere while the value went elsewhere is exactly
			// the bug this guards against.
			mustFollow := func(flag, want string) {
				t.Helper()
				for i, a := range args {
					if a == flag {
						if i+1 >= len(args) {
							t.Errorf("%s is the last argument, with no value", flag)
							return
						}
						if args[i+1] != want {
							t.Errorf("%s = %q, want %q", flag, args[i+1], want)
						}
						return
					}
				}
				t.Errorf("cosign was called without %s: %v", flag, args)
			}
			mustFollow("--certificate-identity-regexp", identityRegexp)
			mustFollow("--certificate-oidc-issuer", oidcIssuer)

			for _, forbidden := range []string{"--insecure-ignore-tlog", "--insecure-ignore-sct"} {
				for _, a := range args {
					if strings.HasPrefix(a, forbidden) {
						t.Errorf("cosign was called with %s, which disables the check", a)
					}
				}
			}

			// The signature must be checked over the same bytes the checksum
			// lookup then reads.
			want := fmt.Sprintf("%x", sha256.Sum256(fx.assets["checksums.txt"]))
			if blobSHA != want {
				t.Errorf("cosign verified a blob with digest %s, but checksums.txt is %s", blobSHA, want)
			}
		})
	}
}

// CATCHES: the lenient default coming back.
//
// Until 2026-09, both scripts printed a line and installed anyway when the
// signature could not be checked. That was the default path, so it was the
// path essentially every install took: v0.5.0 ships no checksums.txt.sig at
// all, and cosign is not on a typical machine. checksums.txt comes from the
// same release as the archive, so against anyone who can write to that release
// it agrees with whatever they put there — the lenient path bought a
// corruption check and nothing else, while the README promised a signature.
//
// Both reasons are tested, because they fail in different places in the script:
// one before cosign would be invoked at all, one after the .sig fetch 404s.
func TestUnsignedReleaseIsRefusedByDefault(t *testing.T) {
	t.Parallel()
	for _, runner := range []struct {
		name string
		run  func(*testing.T, *fakeGitHub, *runOpts) result
	}{{"sh", runSh}, {"ps1", runPs1}} {
		t.Run(runner.name, func(t *testing.T) {
			t.Run("cosign_not_installed", func(t *testing.T) {
				t.Parallel()
				fx := buildFixtures(t)
				g := newFakeGitHub(t, fx)
				argv := filepath.Join(t.TempDir(), "argv.log")

				res := runner.run(t, g, &runOpts{withoutCosign: true, argvLog: argv})
				assertRefused(t, res, "cosign is not installed")
				assertNotExtracted(t, res)

				// The refusal has to say what to do about it, or it just gets
				// worked around with a download from the releases page.
				if !strings.Contains(res.out(), envAllowUnsigned) {
					t.Errorf("the refusal does not name %s, the one way past it\n%s", envAllowUnsigned, res.out())
				}
				if _, err := os.Stat(argv); err == nil {
					t.Error("cosign was invoked even though it is not on PATH")
				}
			})

			for _, missing := range []string{"checksums.txt.sig", "checksums.txt.pem"} {
				t.Run("release_missing_"+missing, func(t *testing.T) {
					t.Parallel()
					fx := buildFixtures(t)
					delete(fx.assets, missing)
					g := newFakeGitHub(t, fx)
					argv := filepath.Join(t.TempDir(), "argv.log")

					res := runner.run(t, g, &runOpts{argvLog: argv})
					assertRefused(t, res, "without a signature")
					assertNotExtracted(t, res)

					// Installing cosign cannot fix a release that has no
					// signature, so the refusal must not tell anyone to.
					if strings.Contains(res.out(), "Install cosign") {
						t.Errorf("an unsigned release is blamed on the local cosign\n%s", res.out())
					}
					if _, err := os.Stat(argv); err == nil {
						t.Error("cosign was invoked with no signature to check")
					}
				})
			}
		})
	}
}

// CATCHES: the opt-out being honoured only for the literal string "1", and the
// warning that goes with it being dropped or demoted to an ordinary step line.
//
// The whole value of an escape hatch is that it is loud. An unsigned install
// that reads exactly like a verified one is how the old default survived.
func TestAllowUnsignedInstallsWithALoudWarning(t *testing.T) {
	t.Parallel()
	for _, runner := range []struct {
		name string
		run  func(*testing.T, *fakeGitHub, *runOpts) result
		bin  string
	}{{"sh", runSh, "constle"}, {"ps1", runPs1, "constle.exe"}} {
		t.Run(runner.name, func(t *testing.T) {
			for _, value := range []string{"1", "true", "YES"} {
				t.Run("value_"+value, func(t *testing.T) {
					t.Parallel()
					fx := buildFixtures(t)
					g := newFakeGitHub(t, fx)

					res := runner.run(t, g, &runOpts{
						withoutCosign: true,
						env:           map[string]string{envAllowUnsigned: value},
					})
					assertInstalled(t, res, runner.bin)

					if !strings.Contains(res.out(), "cosign is not installed") {
						t.Errorf("the skipped signature check was not reported\n%s", res.out())
					}
					if !strings.Contains(res.out(), "signature NOT checked") {
						t.Errorf("the success line claims more than was verified\n%s", res.out())
					}
					if !strings.Contains(res.out(), envAllowUnsigned) {
						t.Errorf("the output does not say which setting weakened this install\n%s", res.out())
					}

					// scripts/install writes warnings to stderr on purpose, so
					// that `curl | sh | tee log` and a scrollback that kept only
					// the last few lines both still show it. PowerShell's
					// Write-Host goes to stdout whatever colour it is, so this
					// half of the assertion is sh-only rather than fudged into
					// something both can pass.
					if runner.name == "sh" && !strings.Contains(res.stderr, envAllowUnsigned) {
						t.Errorf("the downgrade notice did not reach stderr\nstderr: %s", res.stderr)
					}
				})
			}

			// The other reason: cosign is here, the release is not signed.
			t.Run("release_unsigned", func(t *testing.T) {
				t.Parallel()
				fx := buildFixtures(t)
				delete(fx.assets, "checksums.txt.sig")
				g := newFakeGitHub(t, fx)

				res := runner.run(t, g, &runOpts{
					env: map[string]string{envAllowUnsigned: "1"},
				})
				assertInstalled(t, res, runner.bin)
				if !strings.Contains(res.out(), "without a signature") {
					t.Errorf("an unsigned release was not reported as such\n%s", res.out())
				}
			})
		})
	}
}

// CATCHES: a falsy spelling of the opt-out being treated as opting out.
//
// Nothing pinned this direction before: every test set the old opt-in to a
// truthy value, so a parser that treated any non-empty string as "yes" —
// including "0" and "false" — would have passed the whole suite while doing
// the opposite of what the variable says.
func TestAllowUnsignedFalsySpellingsDoNotOptOut(t *testing.T) {
	t.Parallel()
	for _, runner := range []struct {
		name string
		run  func(*testing.T, *fakeGitHub, *runOpts) result
	}{{"sh", runSh}, {"ps1", runPs1}} {
		t.Run(runner.name, func(t *testing.T) {
			for _, value := range []string{"0", "false", "no", "NO", ""} {
				t.Run("value_"+value, func(t *testing.T) {
					t.Parallel()
					fx := buildFixtures(t)
					g := newFakeGitHub(t, fx)

					res := runner.run(t, g, &runOpts{
						withoutCosign: true,
						env:           map[string]string{envAllowUnsigned: value},
					})
					assertRefused(t, res, "cosign is not installed")
					assertNotExtracted(t, res)
				})
			}
		})
	}
}

// CATCHES: the opt-out reaching the branch it must never reach.
//
// This is the invariant the whole design rests on. CONSTLE_ALLOW_UNSIGNED
// covers "there was nothing to check". A signature that WAS checked and came
// back bad is a different event entirely, and no environment variable may
// forgive it — an override there would turn every blocked network, every
// proxy, every failed fetch into a silent downgrade.
func TestAllowUnsignedDoesNotRescueAFailedSignature(t *testing.T) {
	t.Parallel()
	for _, runner := range []struct {
		name string
		run  func(*testing.T, *fakeGitHub, *runOpts) result
	}{{"sh", runSh}, {"ps1", runPs1}} {
		t.Run(runner.name, func(t *testing.T) {
			t.Parallel()
			fx := buildFixtures(t)
			g := newFakeGitHub(t, fx)

			res := runner.run(t, g, &runOpts{
				argvLog: filepath.Join(t.TempDir(), "argv.log"),
				env: map[string]string{
					envAllowUnsigned: "1",
					stubExitEnv:      "1",
				},
			})
			assertRefused(t, res, "SIGNATURE VERIFICATION FAILED")
			assertNotExtracted(t, res)
		})
	}
}

// CATCHES: the opt-out leaking into link 2 of the chain.
//
// It is named for the signature and must touch nothing else. A tampered
// archive is refused on the checksum alone, opt-out or not.
func TestAllowUnsignedDoesNotWeakenTheChecksum(t *testing.T) {
	t.Parallel()
	for _, runner := range []struct {
		name   string
		run    func(*testing.T, *fakeGitHub, *runOpts) result
		tamper func(*testing.T, *fixtures)
	}{
		{"sh", runSh, func(t *testing.T, f *fixtures) {
			f.assets[f.shArchive] = makeTarGz(t, "constle", tamperedMarker)
		}},
		{"ps1", runPs1, func(t *testing.T, f *fixtures) {
			f.assets[f.psArchive] = makeZip(t, "constle.exe", tamperedMarker)
		}},
	} {
		t.Run(runner.name, func(t *testing.T) {
			t.Parallel()
			fx := buildFixtures(t)
			good := checksumsFor(fx.assets) // digests of the genuine archives
			runner.tamper(t, fx)
			fx.assets["checksums.txt"] = []byte(good)
			g := newFakeGitHub(t, fx)

			res := runner.run(t, g, &runOpts{
				withoutCosign: true,
				env:           map[string]string{envAllowUnsigned: "1"},
			})
			assertRefused(t, res, "CHECKSUM MISMATCH")
			assertNotExtracted(t, res)
		})
	}
}

// CATCHES: CONSTLE_REQUIRE_SIGNATURE=0 reinstating the old lenient default.
//
// The variable was the opt-IN back when leniency was the default. A CI file
// still carrying it must not be silently ignored, and — the part that matters —
// the one spelling that would weaken anything has to be refused rather than
// honoured. Honouring it would reopen the hole by name.
func TestLegacyRequireSignatureIsRedundantAndNeverWeakens(t *testing.T) {
	t.Parallel()
	for _, runner := range []struct {
		name string
		run  func(*testing.T, *fakeGitHub, *runOpts) result
		bin  string
	}{{"sh", runSh, "constle"}, {"ps1", runPs1, "constle.exe"}} {
		t.Run(runner.name, func(t *testing.T) {
			// Truthy: redundant. The install still succeeds, because a
			// verified signature is now what happens anyway.
			for _, value := range []string{"1", "true", "YES"} {
				t.Run("redundant_"+value, func(t *testing.T) {
					t.Parallel()
					fx := buildFixtures(t)
					g := newFakeGitHub(t, fx)

					res := runner.run(t, g, &runOpts{
						env: map[string]string{envRequireSig: value},
					})
					assertInstalled(t, res, runner.bin)
					if !strings.Contains(res.out(), "redundant") {
						t.Errorf("a legacy setting was accepted in silence\n%s", res.out())
					}
				})
			}

			// Falsy: reported and ignored, never honoured.
			for _, value := range []string{"0", "false", "no"} {
				t.Run("ignored_"+value, func(t *testing.T) {
					t.Parallel()
					fx := buildFixtures(t)
					g := newFakeGitHub(t, fx)

					res := runner.run(t, g, &runOpts{
						withoutCosign: true,
						env:           map[string]string{envRequireSig: value},
					})
					assertRefused(t, res, "cosign is not installed")
					assertNotExtracted(t, res)

					if !strings.Contains(res.out(), "is ignored") {
						t.Errorf("%s=%s was honoured or dropped silently instead of being reported\n%s",
							envRequireSig, value, res.out())
					}
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The download host
// ---------------------------------------------------------------------------

// CATCHES: the base-URL guard being dropped, or written as a prefix test.
//
// This is not hypothetical. Before the guard existed, pointing the installer
// at a plain-HTTP host that served a tampered archive together with a
// checksums.txt agreeing with it produced exit 0, "checksum verified", and an
// installed binary of the attacker's choosing. An override chooses the
// publisher, so it has to be held to an authenticated transport.
func TestNonHTTPSBaseURLIsRefused(t *testing.T) {
	t.Parallel()
	hostile := []string{
		"http://evil.example",
		"ftp://evil.example",
		// The near-miss a naive "starts with http://127.0.0.1" check accepts.
		"http://127.0.0.1.evil.example:80",
	}

	for _, runner := range []struct {
		name string
		run  func(*testing.T, *fakeGitHub, *runOpts) result
	}{{"sh", runSh}, {"ps1", runPs1}} {
		t.Run(runner.name, func(t *testing.T) {
			for _, variable := range []string{envBaseURL, envAPIURL} {
				for _, bad := range hostile {
					t.Run(variable+"_"+bad, func(t *testing.T) {
						t.Parallel()
						fx := buildFixtures(t)
						g := newFakeGitHub(t, fx)

						res := runner.run(t, g, &runOpts{
							env: map[string]string{variable: bad},
						})
						assertRefused(t, res, "loopback")

						// And it must refuse before reaching the network.
						if hits := g.hitLog(); len(hits) != 0 {
							t.Errorf("requests were made before the host was rejected: %v", hits)
						}
					})
				}
			}
		})
	}
}

// CATCHES: the --proto / --proto-redir pinning being dropped or mis-quoted in
// scripts/install. Every other case in this file uses a loopback http base,
// where fetch() deliberately omits those flags, so without this case they are
// exercised by nothing and a quoting typo would break every real install with
// the suite still green.
func TestHTTPSDownloadRefusesARedirectToPlainHTTP(t *testing.T) {
	t.Parallel()
	skipIfWindows(t)

	fx := buildFixtures(t)

	// The plain-HTTP endpoint an attacker would redirect to, serving a
	// tampered archive and a checksums.txt that agrees with it.
	evilFx := buildFixtures(t)
	evilFx.assets[evilFx.shArchive] = makeTarGz(t, "constle", tamperedMarker)
	evilFx.assets["checksums.txt"] = []byte(checksumsFor(evilFx.assets))
	evil := newFakeGitHub(t, evilFx)

	// The HTTPS origin, which redirects everything to the plain-HTTP one.
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	// curl needs to trust the test server's certificate.
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: redirector.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o644); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}

	binDir := fakeBin(t, append(baseTools, "sha256sum")...)
	unameShim(t, binDir, "Linux", "x86_64")

	res := run(t, evil, []string{"/bin/sh", repoFile(t, "install")}, &runOpts{
		binDir: binDir,
		env: map[string]string{
			envBaseURL:       redirector.URL,
			envAPIURL:        redirector.URL,
			"CURL_CA_BUNDLE": caFile,
			envVersion:       testTag,
		},
	})

	if res.exit == 0 {
		t.Errorf("an HTTPS download that redirected to plain HTTP was accepted\n%s", res.out())
	}
	assertNothingInstalled(t, res)
	assertNotExtracted(t, res)
	_ = fx
}

// ---------------------------------------------------------------------------
// The digest backends
// ---------------------------------------------------------------------------

// CATCHES: a "no hashing tool, so skip the check" branch. There must not be
// one: the next thing the script does is put a file on PATH.
func TestNoDigestToolIsRefused(t *testing.T) {
	t.Parallel()
	skipIfWindows(t)

	fx := buildFixtures(t)
	g := newFakeGitHub(t, fx)

	binDir := fakeBin(t, baseTools...) // deliberately no sha256sum/shasum/openssl
	unameShim(t, binDir, "Linux", "x86_64")

	res := runSh(t, g, &runOpts{binDir: binDir})
	assertRefused(t, res, "no SHA-256 tool")
}

// CATCHES: the `|| ACTUAL=""` guard being dropped. Without it, `set -e` kills
// the script the moment the digest command substitution fails, so the script
// exits with the tool's own status having printed nothing at all, and the
// carefully written error below it is dead code.
func TestDigestToolFailureIsReported(t *testing.T) {
	t.Parallel()
	skipIfWindows(t)

	fx := buildFixtures(t)
	g := newFakeGitHub(t, fx)

	binDir := fakeBin(t, baseTools...)
	unameShim(t, binDir, "Linux", "x86_64")
	writeShim(t, binDir, "sha256sum", "#!/bin/sh\nexit 3\n")

	res := runSh(t, g, &runOpts{binDir: binDir})
	assertRefused(t, res, "could not compute")
}

// CATCHES: a regression in the per-tool output parsing — notably anything
// anchored on the literal "SHA256(", which OpenSSL 3 does not print (it says
// "SHA2-256("). macOS has no sha256sum and relies on shasum, so this is also
// what gives the macOS path coverage from a Linux runner.
func TestEachDigestBackendWorks(t *testing.T) {
	t.Parallel()
	skipIfWindows(t)

	for _, tool := range []string{"sha256sum", "shasum", "openssl"} {
		t.Run(tool, func(t *testing.T) {
			if _, err := exec.LookPath(tool); err != nil {
				t.Skipf("%s is not installed on this host", tool)
			}
			fx := buildFixtures(t)
			g := newFakeGitHub(t, fx)

			binDir := fakeBin(t, append(baseTools, tool)...)
			unameShim(t, binDir, "Linux", "x86_64")

			res := runSh(t, g, &runOpts{binDir: binDir})
			assertInstalled(t, res, "constle")
		})
	}
}

// ---------------------------------------------------------------------------
// Platform mapping
// ---------------------------------------------------------------------------

// CATCHES: the OS/arch mapping drifting from the names GoReleaser actually
// produces, which would make the checksums lookup fail for a whole platform
// while every other test still passed.
func TestArchiveNameMatchesTheReleaseLayout(t *testing.T) {
	t.Parallel()
	skipIfWindows(t)

	for _, tc := range []struct {
		system, machine string
		wantAsset       string
		wantRefusal     string
	}{
		{"Linux", "x86_64", "constle_" + testVersion + "_linux_amd64.tar.gz", ""},
		{"Linux", "aarch64", "constle_" + testVersion + "_linux_arm64.tar.gz", ""},
		{"Darwin", "arm64", "constle_" + testVersion + "_darwin_arm64.tar.gz", ""},
		{"Darwin", "x86_64", "constle_" + testVersion + "_darwin_amd64.tar.gz", ""},
		{"Linux", "riscv64", "", "unsupported architecture"},
		{"FreeBSD", "x86_64", "", "unsupported OS"},
	} {
		t.Run(tc.system+"_"+tc.machine, func(t *testing.T) {
			fx := buildFixtures(t)
			g := newFakeGitHub(t, fx)

			binDir := fakeBin(t, append(baseTools, "sha256sum")...)
			unameShim(t, binDir, tc.system, tc.machine)

			res := runSh(t, g, &runOpts{binDir: binDir})

			if tc.wantRefusal != "" {
				assertRefused(t, res, tc.wantRefusal)
				return
			}
			if res.exit != 0 {
				t.Fatalf("exit = %d, want 0\n%s", res.exit, res.out())
			}
			if !g.requested(tc.wantAsset) {
				t.Errorf("installer did not request %s (hits: %v)", tc.wantAsset, g.hitLog())
			}
		})
	}
}

// scripts/install.ps1 gained the release-tag charset guard in this change, so
// it needs its own case: the tag becomes a URL path and the checksums lookup
// key, and with no argument it is whatever the API replied with.
func TestPs1RefusesAHostileReleaseTag(t *testing.T) {
	t.Parallel()
	fx := buildFixtures(t)
	g := newFakeGitHub(t, fx)
	g.tag = "../../evil"

	res := runPs1(t, g, &runOpts{})
	assertRefused(t, res, "does not look like a release tag")
}

// ---------------------------------------------------------------------------
// Cross-file consistency
//
// This test needs no interpreter and never skips. It runs on every platform
// and in every CI leg, so if a rename or a runner change turned the rest of
// this file into a fully-skipped no-op, this would still be holding the line.
// ---------------------------------------------------------------------------

func TestInstallersPinTheSigningIdentity(t *testing.T) {
	t.Parallel()
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(b)
	}
	sh := read("install")
	ps := read("install.ps1")
	readme := read(filepath.Join("..", "README.md"))

	for name, body := range map[string]string{"scripts/install": sh, "scripts/install.ps1": ps, "README.md": readme} {
		if !strings.Contains(body, identityRegexp) {
			t.Errorf("%s does not contain the pinned signing identity byte-for-byte", name)
		}
	}
	for name, body := range map[string]string{"scripts/install": sh, "scripts/install.ps1": ps} {
		if !strings.Contains(body, oidcIssuer) {
			t.Errorf("%s does not pin the OIDC issuer", name)
		}
		if !strings.Contains(body, "--certificate-identity-regexp") {
			t.Errorf("%s calls cosign without --certificate-identity-regexp", name)
		}
		if !strings.Contains(body, "--certificate-oidc-issuer") {
			t.Errorf("%s calls cosign without --certificate-oidc-issuer", name)
		}

		// An env-var allowlist only catches the escape hatches somebody
		// already thought of. This catches the next one.
		//
		// CONSTLE_ALLOW_UNSIGNED is deliberately not on this list, and matches no
		// entry on it: it does not switch verification off, it acknowledges that
		// there was nothing to verify. The names below are the ones that would.
		lower := strings.ToLower(body)
		for _, forbidden := range []string{
			"skip_check", "skip_sig", "skip_verify", "no_verify", "--insecure-",
			"skip_signature", "allow_unverified", "allow_bad_sig", "ignore_sig",
		} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s contains %q, which reads like a way to switch verification off", name, forbidden)
			}
		}
	}

	// The opt-out has to be spelled identically everywhere, including in the
	// README: a refusal that names a variable the script does not read is worse
	// than no refusal, because it sends people to the releases page to download
	// by hand instead.
	for name, body := range map[string]string{"scripts/install": sh, "scripts/install.ps1": ps, "README.md": readme} {
		if !strings.Contains(body, envAllowUnsigned) {
			t.Errorf("%s does not name %s", name, envAllowUnsigned)
		}
	}

	// The README described the old lenient default for as long as it was true.
	// Leaving that text after the default flipped would document a guarantee
	// nobody gets — which is the failure this whole change is about.
	for _, stale := range []string{
		"makes the signature mandatory",
		"enforces the checksum alone",
		"no release publishes one yet",
	} {
		if strings.Contains(readme, stale) {
			t.Errorf("README.md still describes the old lenient installer: %q", stale)
		}
	}

	// The README's claim about the two flags is what these scripts implement;
	// anchored on the text, never a line number.
	if !strings.Contains(readme, "flags are **not optional.**") {
		t.Error("README.md no longer states that the --certificate-* flags are not optional")
	}
}

// A bare `mktemp -d` is a GNU extension; BSD mktemp, which is what macOS
// ships, needs a template or -t. Everything in the installer hangs off that
// directory, so this failing on its own is far easier to read than twenty
// simultaneous verification failures.
func TestMktempFallbackWorks(t *testing.T) {
	t.Parallel()
	skipIfWindows(t)

	out, err := exec.Command("/bin/sh", "-c", `mktemp -d 2>/dev/null || mktemp -d -t constle`).Output()
	if err != nil {
		t.Fatalf("neither mktemp form works on this host: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Fatal("mktemp produced no directory")
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("mktemp did not create a directory: %v", err)
	}
}
