package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/constle/constle/pkg/manifest"
)

// withCapturedIdentityWarn redirects warnUnverifiableIdentity output into a
// buffer for the duration of one test, restoring the writer afterwards.
func withCapturedIdentityWarn(t *testing.T) *bytes.Buffer {
	t.Helper()

	orig := identityWarnOut
	t.Cleanup(func() { identityWarnOut = orig })

	buf := &bytes.Buffer{}
	identityWarnOut = buf
	return buf
}

func identityManifest(name, did string) *manifest.AgentManifest {
	return &manifest.AgentManifest{
		APIVersion: "constle.dev/v1alpha1",
		Kind:       "AgentManifest",
		Identity:   manifest.Identity{Name: name, DID: did},
	}
}

func TestWarnUnverifiableIdentityMissingKey(t *testing.T) {
	buf := withCapturedIdentityWarn(t)

	// An agent name that cannot have a local identity on any machine running
	// the tests — Load reads only, so touching the real home is safe.
	m := identityManifest(
		"constle-test-no-such-identity-3f9c2a",
		"did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99mXQkL3vUbEr8W3hosJqFr",
	)
	warnUnverifiableIdentity(m)

	out := buf.String()
	if !strings.Contains(out, "NOT usable") {
		t.Errorf("expected an unusable-identity warning, got: %q", out)
	}
	if !strings.Contains(out, "constle identity create") {
		t.Errorf("warning does not tell the user how to fix it: %q", out)
	}
}

func TestWarnUnverifiableIdentitySilentWithoutDID(t *testing.T) {
	buf := withCapturedIdentityWarn(t)

	warnUnverifiableIdentity(identityManifest("any-agent", ""))

	if out := buf.String(); out != "" {
		t.Errorf("expected no warning when identity.did is absent, got: %q", out)
	}
}

func TestLoadRunIdentityFailsClosedWhenMissing(t *testing.T) {
	m := identityManifest(
		"constle-test-no-such-identity-3f9c2a",
		"did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99mXQkL3vUbEr8W3hosJqFr",
	)

	_, err := loadRunIdentity(m)
	if err == nil {
		t.Fatal("loadRunIdentity() succeeded without a local key, want fail-closed error")
	}
	if !strings.Contains(err.Error(), "refusing to run unsigned") {
		t.Errorf("error %q does not state the fail-closed refusal", err)
	}
	if !strings.Contains(err.Error(), "constle identity create") {
		t.Errorf("error %q does not tell the user how to create the identity", err)
	}
}

func TestParseIdentityCreateArgs(t *testing.T) {
	name, owner, err := parseIdentityCreateArgs([]string{"--owner=a@b.c", "my-agent"})
	if err != nil || name != "my-agent" || owner != "a@b.c" {
		t.Errorf("got (%q, %q, %v), want (my-agent, a@b.c, nil)", name, owner, err)
	}

	for _, args := range [][]string{
		{},                          // name required
		{"--bogus", "my-agent"},     // unknown flag
		{"my-agent", "extra-agent"}, // too many names
	} {
		if _, _, err := parseIdentityCreateArgs(args); err == nil {
			t.Errorf("parseIdentityCreateArgs(%v) succeeded, want error", args)
		}
	}
}

func TestParseAuditVerifyArgs(t *testing.T) {
	got, err := parseAuditVerifyArgs([]string{"--did=did:key:zX", "log.jsonl"})
	if err != nil || got.path != "log.jsonl" || got.did != "did:key:zX" ||
		got.approverPubkey != "" || got.agentfile != "" {
		t.Errorf("got (%+v, %v), want path=log.jsonl did=did:key:zX", got, err)
	}

	// --approver-pubkey pins the human-gate approver key, independently of
	// --did, which pins the agent identity the log is signed with.
	got, err = parseAuditVerifyArgs([]string{"--approver-pubkey=did:key:zA", "log.jsonl"})
	if err != nil || got.path != "log.jsonl" || got.did != "" || got.approverPubkey != "did:key:zA" {
		t.Errorf("got (%+v, %v), want path=log.jsonl approverPubkey=did:key:zA", got, err)
	}

	// --agentfile supplies both, and parsing must not touch the file.
	got, err = parseAuditVerifyArgs([]string{"--agentfile=/nonexistent/Agentfile.yaml", "log.jsonl"})
	if err != nil || got.agentfile != "/nonexistent/Agentfile.yaml" {
		t.Errorf("got (%+v, %v), want the agentfile recorded without reading it", got, err)
	}

	for _, args := range [][]string{
		{},                     // path required
		{"--bogus", "l.j"},     // unknown flag
		{"a.jsonl", "b.jsonl"}, // too many paths
	} {
		if _, err := parseAuditVerifyArgs(args); err == nil {
			t.Errorf("parseAuditVerifyArgs(%v) succeeded, want error", args)
		}
	}
}

// writeAgentfile writes a minimal valid Agentfile declaring the given
// identity DID and approver pubkey, and returns its path.
func writeAgentfile(t *testing.T, didStr, approverPubkey string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("apiVersion: constle.dev/v1alpha1\nkind: AgentManifest\nidentity:\n  name: pin-test\n")
	if didStr != "" {
		fmt.Fprintf(&b, "  did: %q\n", didStr)
	}
	if approverPubkey != "" {
		b.WriteString("human_gates:\n  enabled: true\n")
		fmt.Fprintf(&b, "  approver_pubkey: %q\n", approverPubkey)
	}
	path := filepath.Join(t.TempDir(), "Agentfile.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write Agentfile: %v", err)
	}
	return path
}

// testDID and testApproverKey are two distinct, structurally valid did:key
// Ed25519 strings.
const (
	testDIDKey      = "did:key:z6MkvCPu8KZHXXEiFNkN9PF8zgczaW3FXrZB911vDYbK8cfx"
	testApproverKey = "did:key:z6MkgZ9rP6b8ugnXJwtJzQc3yheTPPU7ZBLgdYuVZGEs3eH6"
)

// TestResolvePinsFromAgentfile: one flag replaces two pasted did:key strings.
func TestResolvePinsFromAgentfile(t *testing.T) {
	path := writeAgentfile(t, testDIDKey, testApproverKey)

	gotDID, gotApprover, err := auditVerifyArgs{agentfile: path}.resolvePins()
	if err != nil {
		t.Fatalf("resolvePins() error: %v", err)
	}
	if gotDID != testDIDKey || gotApprover != testApproverKey {
		t.Errorf("resolvePins() = (%q, %q), want the Agentfile's two keys", gotDID, gotApprover)
	}
}

// TestResolvePinsWithoutAgentfile: the explicit flags still stand alone.
func TestResolvePinsWithoutAgentfile(t *testing.T) {
	gotDID, gotApprover, err := auditVerifyArgs{
		did: testDIDKey, approverPubkey: testApproverKey,
	}.resolvePins()
	if err != nil || gotDID != testDIDKey || gotApprover != testApproverKey {
		t.Errorf("resolvePins() = (%q, %q, %v), want the flags unchanged", gotDID, gotApprover, err)
	}
}

// TestResolvePinsRefusesContradiction: two different answers to "which key is
// this log held to" is the operator's to settle, not this command's to pick.
func TestResolvePinsRefusesContradiction(t *testing.T) {
	path := writeAgentfile(t, testDIDKey, testApproverKey)

	for _, tc := range []struct {
		name string
		args auditVerifyArgs
		want string
	}{
		{"did", auditVerifyArgs{agentfile: path, did: testApproverKey}, "identity.did"},
		{"approver", auditVerifyArgs{agentfile: path, approverPubkey: testDIDKey}, "approver_pubkey"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := tc.args.resolvePins()
			if err == nil {
				t.Fatal("resolvePins() accepted a flag contradicting the Agentfile")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error did not name %s: %v", tc.want, err)
			}
		})
	}

	// Saying the same thing twice is not a contradiction.
	if _, _, err := (auditVerifyArgs{agentfile: path, did: testDIDKey}).resolvePins(); err != nil {
		t.Errorf("resolvePins() refused a flag that agrees with the Agentfile: %v", err)
	}
}

// TestResolvePinsMissingAgentfile fails loudly rather than degrading to an
// unpinned verification that looks like a pinned one.
func TestResolvePinsMissingAgentfile(t *testing.T) {
	_, _, err := auditVerifyArgs{agentfile: filepath.Join(t.TempDir(), "nope.yaml")}.resolvePins()
	if err == nil {
		t.Fatal("resolvePins() accepted a missing Agentfile")
	}
}

// TestDescribePinsNamesWhatWasNotPinned: an Agentfile that supplies nothing
// must not be reported as though it had pinned something.
func TestDescribePinsNamesWhatWasNotPinned(t *testing.T) {
	if got := describePins("", ""); !strings.Contains(got, "nothing was pinned") {
		t.Errorf("describePins(\"\", \"\") = %q, want it to say nothing was pinned", got)
	}
	if got := describePins(testDIDKey, ""); !strings.Contains(got, "unpinned") {
		t.Errorf("describePins(did, \"\") = %q, want it to flag the unpinned gate decisions", got)
	}
}
