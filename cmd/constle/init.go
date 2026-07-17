package main

// init.go — constle init
//
// Creates agent.yaml in the current directory with sensible defaults
// and inline comments explaining every field.
//
// The generated file is intentionally conservative:
//   - isolation is inferred from capabilities (read_file + write_file → process)
//   - network egress is restricted with a placeholder allowlist
//   - human gates are enabled with approval required for the three highest-risk actions
//   - spending caps and a 5-minute timeout are set so the agent cannot run indefinitely
//
// The user edits the file, then runs:
//   constle validate agent.yaml
//   constle run     agent.yaml

import (
	"fmt"
	"os"
)

// defaultAgentYAML is the template written by `constle init`.
// It covers every section of AgentManifest with working defaults
// and a comment on each field explaining what it controls.
const defaultAgentYAML = `apiVersion: constle.dev/v1alpha1
kind: AgentManifest

# ---------------------------------------------------------------------------
# identity — who this agent is
# ---------------------------------------------------------------------------
identity:
  # Human-readable name. Use lowercase letters, digits, and hyphens.
  name: my-agent

  # Semantic version of this agent definition (semver).
  version: "1.0.0"

  # Optional: email or team identifier of the person responsible for this agent.
  owner: ""

# ---------------------------------------------------------------------------
# sandbox — how to run the agent in isolation
# ---------------------------------------------------------------------------
sandbox:
  # Docker image that contains your agent code.
  # Use a pinned digest in production: python:3.11-slim@sha256:...
  image: python:3.11-slim

  # Entrypoint override. Remove this key to use the image's default CMD.
  command: ["python", "/workspace/agent.py"]

  # Memory limit in megabytes. The container is OOM-killed if it exceeds this.
  memory_mb: 512

  # Ephemeral disk quota in megabytes.
  disk_mb: 2048

  network:
    # Egress policy.
    #   restricted — only hosts listed in allowed_hosts may be contacted
    #   open       — unrestricted outbound access (not recommended)
    #   none       — no outbound network at all
    egress: restricted

    # Hosts the agent is allowed to reach.
    # Only meaningful when egress is "restricted".
    # Add exactly the domains your agent needs; everything else is blocked.
    allowed_hosts:
      - api.openai.com   # replace or extend with the APIs your agent uses

# ---------------------------------------------------------------------------
# capabilities — what the agent is permitted to do
# ---------------------------------------------------------------------------
# Constle infers the minimum required sandbox isolation from this list:
#
#   read_file / write_file                → process isolation
#   web_search / external_api            → network isolation
#   spawn_subagent / external_transfer /
#   delete_records                        → kernel isolation (Firecracker)
#
# Capabilities not listed here are denied at runtime.
#
# Full list of recognised values:
#   read_file         write_file        web_search      external_api
#   send_email        spawn_subagent    external_transfer  delete_records
capabilities:
  - read_file    # mount a host directory and read files from it
  - write_file   # write results back to a mounted directory

# ---------------------------------------------------------------------------
# mcp — Model Context Protocol servers the agent may call
# ---------------------------------------------------------------------------
# Every declared server is reachable ONLY through constle's MCP gate proxy:
# the agent receives a CONSTLE_MCP_<ID>_URL environment variable pointing at
# the gate, the real URL below never enters the sandbox, and the sandbox
# network blocks every direct path. Tool calls matching human_gates
# entries below pause for approval at the gate.
#
# mcp:
#   servers:
#       # Unique name; also names the env var (email -> CONSTLE_MCP_EMAIL_URL).
#     - id: email
#       # Real streamable-HTTP endpoint of the MCP server (host side only).
#       url: "http://192.168.1.50:9000/mcp"
#       # Optional tool allowlist; the gate rejects tools not listed here.
#       # Omit to allow every tool the server offers.
#       tools: [send_email, list_inbox]

# ---------------------------------------------------------------------------
# spending — cost guardrails applied across the agent's lifetime
# ---------------------------------------------------------------------------
spending:
  # Hard cap on API / LLM costs for a single invocation.
  max_per_run_usd: "0.50"

  # Hard cap per UTC calendar day.
  max_per_day_usd: "5.00"

  # Hard cap per calendar month.
  max_per_month_usd: "50.00"

# ---------------------------------------------------------------------------
# limits — runtime constraints that constle actively enforces
# ---------------------------------------------------------------------------
limits:
  # Wall-clock timeout in seconds. Constle sends SIGTERM then cleans up when
  # this elapses. Set to 0 to disable (not recommended in production).
  max_duration_seconds: 300

# ---------------------------------------------------------------------------
# human_gates — when to pause and wait for a human to approve an action
# ---------------------------------------------------------------------------
# Enforcement: an entry gates an MCP tool call when it is an EXACT,
# case-sensitive match for the tool's name on a server declared under mcp
# above (e.g. the entry "send_email" pauses every tools/call named
# send_email). Entries that match no declared MCP tool are NOT enforced —
# constle warns about them at validate and run time.
human_gates:
  # Master switch. Set to false only for fully automated pipelines where
  # no human can reasonably be reached during a run.
  enabled: true

  # MCP tool names that must be explicitly approved before each call.
  # Add the risky tools of the servers you declare under mcp above, e.g.:
  #   require_approval_for:
  #     - send_email
  require_approval_for: []

  # How long a paused call waits for a human decision. Default: 300.
  approval_timeout_seconds: 300

  # What to do when the approver does not respond in time.
  #   abort   — stop the run and log a timeout event (safe default)
  #   proceed — continue without approval (use only for low-risk actions)
  on_timeout: abort

  # Where to announce a triggered gate, in addition to the terminal prompt.
  # url_secret_ref names an environment variable holding the webhook URL.
  # notify:
  #   - channel: webhook
  #     url_secret_ref: HUMAN_GATE_WEBHOOK_URL

# ---------------------------------------------------------------------------
# compliance — audit and regulatory metadata
# ---------------------------------------------------------------------------
compliance:
  # How much detail to record in the audit log.
  #   none | minimal | standard | verbose
  audit_log_level: standard

  # Regulatory frameworks this deployment must satisfy.
  # Examples: EU_AI_ACT, SOC2_TYPE2, HIPAA, PCI_DSS
  # Leave empty if none apply.
  frameworks: []

# ---------------------------------------------------------------------------
# metadata — human-readable context (not enforced at runtime)
# ---------------------------------------------------------------------------
metadata:
  # One-sentence description of what this agent does.
  description: "Describe what this agent does."

  # Author identifier (email, DID, or GitHub handle).
  author: ""

  # SPDX license identifier.
  license: "Apache-2.0"

  # Free-form key/value labels for internal tooling, cost attribution, etc.
  labels:
    use_case: general
    maturity: experimental
`

func cmdInit() error {
	const filename = "agent.yaml"

	// Refuse to overwrite an existing file — the user's work is never destroyed silently.
	_, statErr := os.Stat(filename)
	if statErr == nil {
		return fmt.Errorf("%s already exists — rename or remove it first", filename)
	}
	if !os.IsNotExist(statErr) {
		return fmt.Errorf("cannot check %s: %w", filename, statErr)
	}

	if err := os.WriteFile(filename, []byte(defaultAgentYAML), 0o644); err != nil {
		return fmt.Errorf("cannot write %s: %w", filename, err)
	}

	printf("✓ created %s\n\n", filename)
	printf("  next steps:\n")
	printf("    1. edit %s — set your image, command, and allowed_hosts\n", filename)
	printf("    2. constle validate %s\n", filename)
	printf("    3. constle run %s\n\n", filename)

	return nil
}
