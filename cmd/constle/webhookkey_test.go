package main

import (
	"strings"
	"testing"

	"github.com/constle/constle/internal/webhookkey"
	"github.com/constle/constle/pkg/did"
)

func TestParseWebhookKeygenArgs(t *testing.T) {
	name, err := parseWebhookKeygenArgs([]string{"prod-approver"})
	if err != nil || name != "prod-approver" {
		t.Errorf("got (%q, %v), want (prod-approver, nil)", name, err)
	}

	for _, args := range [][]string{
		{},                                  // name required
		{"--bogus", "prod-approver"},        // unknown flag
		{"prod-approver", "extra-argument"}, // too many names
	} {
		if _, err := parseWebhookKeygenArgs(args); err == nil {
			t.Errorf("parseWebhookKeygenArgs(%v) succeeded, want error", args)
		}
	}
}

func TestCmdWebhookKeygenGeneratesValidDID(t *testing.T) {
	// webhookkey has no exported root override (its rootOverride is
	// package-private), so isolation from cmd/constle's black-box test goes
	// through HOME instead — same effect, since webhookkey.Root() resolves
	// via homedir.InvokingUserHome(), which reads $HOME outside of sudo.
	t.Setenv("HOME", t.TempDir())

	if err := cmdWebhookKeygen("test-approver"); err != nil {
		t.Fatalf("cmdWebhookKeygen() error: %v", err)
	}

	kp, err := webhookkey.Load("test-approver")
	if err != nil {
		t.Fatalf("Load() after cmdWebhookKeygen() error: %v", err)
	}
	if err := did.Validate(kp.DID()); err != nil {
		t.Errorf("generated DID %q is not well-formed: %v", kp.DID(), err)
	}
	if !strings.Contains(kp.DID(), "did:key:z") {
		t.Errorf("DID %q does not look like a did:key string", kp.DID())
	}
}
