// Tests for .github/workflows/release.yaml.
//
// The release workflow is the root of the trust chain both installers depend
// on: it is the thing whose identity scripts/install pins, and the only thing
// that can produce a signature that identity will accept. Nothing else in CI
// checks it - actionlint is not a dependency here, and a workflow that grants
// itself too much or floats its dependencies still runs green.
//
// These tests read the file as data. They need no network, no runner and no
// interpreter, so they run in all three CI legs alongside the installer tests.
//
// A note on the parser: yaml.v3 ignores fields the structs below do not name,
// so a typo in a struct tag would produce an empty result and a vacuously
// passing test. Every test therefore asserts that it found something before it
// asserts anything about it. (The same class of silent-drop that C-36 tracks in
// pkg/manifest/parser.go.)
package scripts_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const releaseWorkflowPath = "../.github/workflows/release.yaml"

type workflowStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]string `yaml:"with"`
}

type workflowJob struct {
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

type releaseWorkflow struct {
	Permissions map[string]string      `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

// loadReleaseWorkflow returns the parsed workflow and its raw bytes. Both are
// needed: `uses:` values come from the parse, while the version comment that
// makes a SHA pin readable is a comment, which the parse throws away.
func loadReleaseWorkflow(t *testing.T) (releaseWorkflow, string) {
	t.Helper()
	raw, err := os.ReadFile(releaseWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", releaseWorkflowPath, err)
	}
	var wf releaseWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse %s: %v", releaseWorkflowPath, err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatalf("%s parsed to zero jobs", releaseWorkflowPath)
	}
	return wf, string(raw)
}

// A full 40-character commit SHA, optionally with a subdirectory before the @.
var pinnedUses = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(/[^@]+)?@[0-9a-f]{40}$`)

// An exact version, not a range and not "latest".
var exactVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// A whole YAML line that pins a tool to a moving target.
var floatingVersion = regexp.MustCompile(`(?m)^[ \t]*(version|cosign-release):[ \t]*['"]?latest['"]?[ \t]*$`)

// CATCHES: an action reverting to a mutable tag.
//
// `@v4` is a ref the action's owner can repoint at any time. Inside a job that
// holds id-token: write, whoever moves that tag gets to sign as this project on
// the next release - the tj-actions/changed-files shape exactly. This is the
// test that makes such a change fail in CI rather than at the next tag push.
func TestReleaseWorkflowPinsEveryActionToASha(t *testing.T) {
	t.Parallel()
	wf, raw := loadReleaseWorkflow(t)

	found := 0
	for jobName, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			found++
			if !pinnedUses.MatchString(step.Uses) {
				t.Errorf("job %q uses %q, which is not pinned to a full 40-character commit SHA", jobName, step.Uses)
				continue
			}
			// A bare SHA is unreadable, so the convention is a trailing
			// comment naming the version it was resolved from. Without it
			// nobody can tell a stale pin from a current one.
			if !hasVersionComment(raw, step.Uses) {
				t.Errorf("job %q pins %q with no trailing \"# v...\" comment saying which version that SHA is", jobName, step.Uses)
			}
		}
	}
	if found == 0 {
		t.Fatal("no `uses:` steps found at all — the struct tags above have drifted from the workflow")
	}
}

func hasVersionComment(raw, uses string) bool {
	for _, line := range strings.Split(raw, "\n") {
		if !strings.Contains(line, uses) {
			continue
		}
		_, comment, ok := strings.Cut(line, "#")
		if ok && strings.HasPrefix(strings.TrimSpace(comment), "v") {
			return true
		}
	}
	return false
}

// CATCHES: `version: latest` coming back for any tool in the release job.
//
// Pinning the ACTION is only half of it. goreleaser-action's `version` input
// resolves the GoReleaser CLI at run time, and cosign-installer's
// `cosign-release` input defaults to whatever that action ships that day. Both
// binaries run inside the job that holds the signing identity, so both are
// dependencies of the signature whether or not they look like one.
func TestReleaseWorkflowPinsToolVersions(t *testing.T) {
	t.Parallel()
	wf, raw := loadReleaseWorkflow(t)

	// Anchored to a whole YAML line, not searched for anywhere in the file:
	// the prose in this workflow's own comments says "version: latest" while
	// explaining why it is gone, and a substring search would match that.
	if loc := floatingVersion.FindString(raw); loc != "" {
		t.Errorf("the workflow still contains %q, which resolves a tool at run time", strings.TrimSpace(loc))
	}

	sawGoreleaser, sawCosign := false, false
	for jobName, job := range wf.Jobs {
		for _, step := range job.Steps {
			switch {
			case strings.HasPrefix(step.Uses, "goreleaser/goreleaser-action@"):
				sawGoreleaser = true
				if v := step.With["version"]; !exactVersion.MatchString(v) {
					t.Errorf("job %q runs GoReleaser with version %q; want an exact vX.Y.Z", jobName, v)
				}
			case strings.HasPrefix(step.Uses, "sigstore/cosign-installer@"):
				sawCosign = true
				if v := step.With["cosign-release"]; !exactVersion.MatchString(v) {
					t.Errorf("job %q installs cosign with cosign-release %q; want an exact vX.Y.Z. "+
						"Left unset, the cosign that signs the release is whichever one the action defaults to that day", jobName, v)
				}
			}
		}
	}
	if !sawGoreleaser {
		t.Error("no goreleaser-action step found — this test is no longer checking anything")
	}
	if !sawCosign {
		t.Error("no cosign-installer step found — this test is no longer checking anything")
	}
}

// CATCHES: the write permissions drifting back to workflow scope, or the
// attestation and the release toolchain sharing a job again.
//
// A permissions block at workflow level applies to every step in every job,
// including third-party actions. id-token: write is the sharp one: it mints the
// OIDC token Fulcio certifies as this workflow, which is the identity both
// installers pin. Anything holding it can sign arbitrary bytes as this project.
func TestReleaseWorkflowPermissionsAreLeastPrivilege(t *testing.T) {
	t.Parallel()
	wf, _ := loadReleaseWorkflow(t)

	if len(wf.Permissions) == 0 {
		t.Fatal("the workflow declares no top-level permissions block; without one, jobs inherit the repository default")
	}
	for scope, level := range wf.Permissions {
		if level != "read" && level != "none" {
			t.Errorf("workflow-level permissions grant %s: %s; the baseline must be read-only and every write granted per job", scope, level)
		}
	}

	for jobName, job := range wf.Jobs {
		if len(job.Permissions) == 0 {
			t.Errorf("job %q declares no permissions block of its own", jobName)
			continue
		}
		// The release job runs a third-party toolchain with contents: write.
		// Handing it attestations: write as well lets a compromised toolchain
		// mint provenance for subjects it did not build.
		if job.Permissions["contents"] == "write" && job.Permissions["attestations"] == "write" {
			t.Errorf("job %q holds contents: write and attestations: write together; publishing and attesting belong in separate jobs", jobName)
		}
	}

	// The job that checks the published release must not be able to repair it.
	verify, ok := wf.Jobs["verify"]
	if !ok {
		t.Fatal("no `verify` job — see TestReleaseWorkflowVerifiesItsOwnSignature")
	}
	for scope, level := range verify.Permissions {
		if level == "write" {
			t.Errorf("the verify job holds %s: write; it exists to refuse a bad release, not to fix one", scope)
		}
	}
}

// CATCHES: renaming or moving the release workflow.
//
// The certificate identity a keyless signature carries is
// https://github.com/OWNER/REPO/<workflow path>@<ref>, and that path is a
// literal inside scripts/install, scripts/install.ps1 and README.md. Renaming
// this file to release.yml, or moving the signing step into a reusable
// workflow, changes the identity every already-shipped installer is pinned to —
// and every one of them would then refuse every future release. There is no
// way to fix that after the fact for a script a user already downloaded.
func TestReleaseWorkflowPathMatchesThePinnedIdentity(t *testing.T) {
	t.Parallel()

	if _, err := os.Stat(releaseWorkflowPath); err != nil {
		t.Fatalf("the release workflow is not at .github/workflows/release.yaml: %v", err)
	}

	// The pin is a regular expression, so the path inside it is escaped.
	// Unescaping is enough to compare it to a real path.
	wantPath := ".github/workflows/" + filepath.Base(releaseWorkflowPath)
	if !strings.Contains(strings.ReplaceAll(identityRegexp, `\.`, "."), wantPath) {
		t.Errorf("the pinned signing identity does not name %s:\n  %s", wantPath, identityRegexp)
	}

	// A second workflow under a name that differs only by extension would make
	// it ambiguous which file actually signs.
	if _, err := os.Stat("../.github/workflows/release.yml"); err == nil {
		t.Error("both release.yaml and release.yml exist; only the one named in the pinned identity can sign")
	}
}

// CATCHES: the release workflow going back to trusting its own exit code.
//
// This is the test for the failure that actually happened. Release v0.5.0 was
// published by a successful run of this workflow with no checksums.txt.sig and
// no checksums.txt.pem — the tag pointed at a commit whose .goreleaser.yaml had
// no signs block — and the run was green, because nothing checked the output.
// Every installer that requires a verified signature refuses that release.
//
// Verifying with a different identity than the installers pin would prove
// nothing about whether an install will succeed, so the literals are compared
// byte-for-byte against the same constants install_test.go asserts on.
func TestReleaseWorkflowVerifiesItsOwnSignature(t *testing.T) {
	t.Parallel()
	wf, _ := loadReleaseWorkflow(t)

	var verifyScript string
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if strings.Contains(step.Run, "cosign verify-blob") {
				verifyScript += step.Run
			}
		}
	}
	if verifyScript == "" {
		t.Fatal("no step runs `cosign verify-blob`; the workflow does not check that what it published can be verified")
	}

	for _, want := range []string{
		identityRegexp,
		oidcIssuer,
		"--certificate-identity-regexp",
		"--certificate-oidc-issuer",
	} {
		if !strings.Contains(verifyScript, want) {
			t.Errorf("the self-verification step does not use %q, so it is not verifying what the installers verify", want)
		}
	}
}
