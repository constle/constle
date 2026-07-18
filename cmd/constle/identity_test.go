package main

import (
	"bytes"
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
	path, did, err := parseAuditVerifyArgs([]string{"--did=did:key:zX", "log.jsonl"})
	if err != nil || path != "log.jsonl" || did != "did:key:zX" {
		t.Errorf("got (%q, %q, %v), want (log.jsonl, did:key:zX, nil)", path, did, err)
	}

	for _, args := range [][]string{
		{},                     // path required
		{"--bogus", "l.j"},     // unknown flag
		{"a.jsonl", "b.jsonl"}, // too many paths
	} {
		if _, _, err := parseAuditVerifyArgs(args); err == nil {
			t.Errorf("parseAuditVerifyArgs(%v) succeeded, want error", args)
		}
	}
}
