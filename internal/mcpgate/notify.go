package mcpgate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/constle/constle/pkg/manifest"
)

// WebhookNotifier POSTs gate-trigger events to the webhooks configured in
// human_gates.notify. Delivery is fire-and-forget: the gate never blocks on
// a notification, and a failed delivery never blocks the approval flow —
// the local prompt/timeout path is the enforcement, the webhook is the
// signal. Failures are reported on Out so they are visible, not silent.
type WebhookNotifier struct {
	// URLs are the resolved webhook endpoints.
	URLs []string

	// Out receives delivery warnings (the CLI's locked stdout writer).
	Out io.Writer

	// Client defaults to a 10-second-timeout HTTP client.
	Client *http.Client
}

// NewWebhookNotifier resolves human_gates.notify webhook URLs from the
// environment (url_secret_ref names the variable). Unset variables produce
// a warning on out and are skipped — the gate still enforces locally.
// Returns nil when no webhook ends up configured.
func NewWebhookNotifier(gates manifest.HumanGates, out io.Writer) *WebhookNotifier {
	var urls []string
	for _, n := range gates.Notify {
		if n.Channel != "webhook" {
			continue // unreachable after manifest validation; belt and braces
		}
		url := os.Getenv(n.URLSecretRef)
		if url == "" {
			fmt.Fprintf(out, "⚠️  warning: human_gates.notify webhook env %s is not set — "+
				"gate events will only be visible on this terminal\n", n.URLSecretRef)
			continue
		}
		urls = append(urls, url)
	}
	if len(urls) == 0 {
		return nil
	}
	return &WebhookNotifier{URLs: urls, Out: out}
}

// webhookPayload is the JSON body delivered for a triggered gate.
type webhookPayload struct {
	Event          string          `json:"event"`
	RunID          string          `json:"run_id"`
	AgentName      string          `json:"agent_name"`
	Server         string          `json:"server"`
	Tool           string          `json:"tool"`
	Arguments      json.RawMessage `json:"arguments,omitempty"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	OnTimeout      string          `json:"on_timeout"`
	TriggeredAt    time.Time       `json:"triggered_at"`
}

// NotifyTriggered delivers a gate_triggered event to every configured
// webhook, each in its own goroutine.
func (n *WebhookNotifier) NotifyTriggered(req Request) {
	payload, err := json.Marshal(webhookPayload{
		Event:          "gate_triggered",
		RunID:          req.RunID,
		AgentName:      req.AgentName,
		Server:         req.ServerID,
		Tool:           req.Tool,
		Arguments:      req.Arguments,
		TimeoutSeconds: req.TimeoutSeconds,
		OnTimeout:      req.OnTimeout,
		TriggeredAt:    time.Now().UTC(),
	})
	if err != nil {
		fmt.Fprintf(n.Out, "⚠️  warning: cannot marshal gate webhook payload: %v\n", err)
		return
	}

	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	for _, url := range n.URLs {
		go func(url string) {
			resp, err := client.Post(url, "application/json", bytes.NewReader(payload))
			if err != nil {
				fmt.Fprintf(n.Out, "⚠️  warning: gate webhook delivery to %s failed: %v\n", url, err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode >= 300 {
				fmt.Fprintf(n.Out, "⚠️  warning: gate webhook %s answered %s\n", url, resp.Status)
			}
		}(url)
	}
}
