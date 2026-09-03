package main

import (
	"fmt"
	"strings"

	"github.com/constle/constle/internal/webhookkey"
)

// parseWebhookKeygenArgs extracts the key name from `constle webhook-keygen`
// arguments. A name is required — the same rule identity create applies —
// so a repeat run without one cannot be mistaken for regenerating the same
// key silently.
func parseWebhookKeygenArgs(args []string) (name string, err error) {
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "-"):
			return "", fmt.Errorf("unknown flag %q\nusage: constle webhook-keygen <name>", arg)
		case name == "":
			name = arg
		default:
			return "", fmt.Errorf("unexpected argument %q", arg)
		}
	}
	if name == "" {
		return "", fmt.Errorf("usage: constle webhook-keygen <name>")
	}
	return name, nil
}

// cmdWebhookKeygen generates a new Ed25519 keypair for the human-gates
// webhook flow and prints the did:key string to paste into
// human_gates.approver_pubkey.
//
// This key is intentionally NOT an agent identity (see internal/webhookkey's
// doc comment and spec/human-gates-webhook.md §2): it authenticates the
// human deciding on a gated call, not the agent whose call is being decided.
func cmdWebhookKeygen(name string) error {
	kp, err := webhookkey.Generate(name)
	if err != nil {
		return err
	}

	printf("\n✓ webhook signing key created: %q\n\n", name)
	printf("  did:       %s\n", kp.DID())
	printf("  key file:  %s (mode 0600 — never leaves this machine)\n", webhookkey.Dir(name))
	printf("\n")
	printf("  this key is NOT an agent identity — it authenticates the human\n")
	printf("  approving gated calls, not the agent making them.\n")
	printf("\n")
	printf("  give the private key file to whoever operates the decision\n")
	printf("  endpoint, and paste the DID into your Agentfile:\n\n")
	printf("    human_gates:\n")
	printf("      approver_pubkey: %s\n", kp.DID())
	printf("\n")
	return nil
}
