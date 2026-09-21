package mcpgate

import (
	"bytes"
	"strings"
	"testing"

	"github.com/constle/constle/pkg/manifest"
)

// TestNewWebhookNotifierIgnoresDisarmedGates: with human_gates.enabled false
// no gate ever triggers, so there is nothing to notify about. Resolving the
// notify block anyway warned that "gate events will only be visible on this
// terminal" — which reads as enforcement having moved somewhere local, when in
// fact no gate is going to fire at all. That is the same false assurance the
// gate reporting was fixed for, reached by a different path.
func TestNewWebhookNotifierIgnoresDisarmedGates(t *testing.T) {
	gates := manifest.HumanGates{
		Enabled:            false,
		RequireApprovalFor: []string{"send_email"},
		Notify: []manifest.NotifyChannel{
			{Channel: "webhook", URLSecretRef: "CONSTLE_TEST_GATE_WEBHOOK"},
		},
	}

	var out bytes.Buffer
	if wn := NewWebhookNotifier(gates, &out); wn != nil {
		t.Errorf("built a notifier for a gate that never triggers: %+v", wn)
	}
	if out.Len() != 0 {
		t.Errorf("warned about a webhook for a disarmed gate: %q", out.String())
	}
}

// TestNewWebhookNotifierWarnsOnUnsetEnvWhenArmed is the other half: with the
// switch on, an unresolvable webhook URL is a real gap and must still be said
// out loud.
func TestNewWebhookNotifierWarnsOnUnsetEnvWhenArmed(t *testing.T) {
	gates := manifest.HumanGates{
		Enabled:            true,
		RequireApprovalFor: []string{"send_email"},
		Notify: []manifest.NotifyChannel{
			{Channel: "webhook", URLSecretRef: "CONSTLE_TEST_GATE_WEBHOOK"},
		},
	}

	var out bytes.Buffer
	if wn := NewWebhookNotifier(gates, &out); wn != nil {
		t.Errorf("notifier = %+v, want nil when the env var is unset", wn)
	}
	if !strings.Contains(out.String(), "CONSTLE_TEST_GATE_WEBHOOK") {
		t.Errorf("want a warning naming the unset env var, got: %q", out.String())
	}
}

// TestNewWebhookNotifierResolvesWhenArmed proves the guard did not disable the
// notifier outright.
func TestNewWebhookNotifierResolvesWhenArmed(t *testing.T) {
	t.Setenv("CONSTLE_TEST_GATE_WEBHOOK", "https://gate.example.com/hook")

	gates := manifest.HumanGates{
		Enabled:            true,
		RequireApprovalFor: []string{"send_email"},
		Notify: []manifest.NotifyChannel{
			{Channel: "webhook", URLSecretRef: "CONSTLE_TEST_GATE_WEBHOOK"},
		},
	}

	var out bytes.Buffer
	wn := NewWebhookNotifier(gates, &out)
	if wn == nil {
		t.Fatal("notifier = nil, want a notifier for an armed gate with a resolved URL")
	}
	if len(wn.URLs) != 1 || wn.URLs[0] != "https://gate.example.com/hook" {
		t.Errorf("URLs = %v, want the resolved webhook", wn.URLs)
	}
	if out.Len() != 0 {
		t.Errorf("unexpected warning: %q", out.String())
	}
}
