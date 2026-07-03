# Constle AgentManifest Specification

**Version:** 0.1.0-draft
**Status:** Draft. Field names and semantics may change before v1.0.
**Last updated:** 2026-06-21
**Source of truth:** `pkg/manifest/manifest.go`
**Canonical URL:** https://constle.dev/spec/agent-manifest

---

## Overview

The AgentManifest (also called the **Agentfile**) is a YAML file that tells the Constle runtime
everything it needs to know about an AI agent: who the agent is, how to run it in isolation,
what it is allowed to do, how much it is allowed to spend, when to stop and ask a human for
approval, and what to log.

The analogy is a Dockerfile. A developer writes one Agentfile and the Constle runtime executes it
the same way on any infrastructure — AWS, GCP, Azure, or a local machine.

**Core design rule:** The manifest declares what the agent *needs*, not how to implement it.
The runtime makes all infrastructure decisions.

---

## Conventions

### Required vs. Optional

A field marked **required** will cause the runtime to reject the manifest if it is absent or empty.

A field marked **optional** may be omitted. Where a default exists it is documented.

### Enforcement labels

Every field in this document carries one of four labels:

| Label | Meaning |
|-------|---------|
| ENFORCED | The runtime actively prevents violations at execution time. If the agent violates this constraint, the runtime stops it. |
| VALIDATED | The runtime checks that the value is well-formed when the manifest is parsed. It does not enforce the constraint during execution. |
| DECLARED | The value is parsed and written to the audit log, but the runtime does not act on it yet. Enforcement is planned for a future version. |
| INFORMATIONAL | The runtime does not read this field at all. It exists for humans and external tooling. |

The distinction between DECLARED and ENFORCED matters. If a field is DECLARED, a developer
cannot rely on the runtime to stop the agent from violating it.

---

## Document Structure

A complete AgentManifest has these top-level sections:

```yaml
apiVersion: constle.dev/v1alpha1   # required
kind: AgentManifest              # required

identity: ...      # who the agent is
sandbox: ...       # how to run and isolate it
capabilities: ...  # what the agent is allowed to do
spending: ...      # budget limits
limits: ...        # hard execution constraints the runtime enforces today
human_gates: ...   # when to pause and ask a human for approval
compliance: ...    # audit logging and regulatory declarations
metadata: ...      # human-readable description, not read by runtime
```

---

## Top-Level Fields

### apiVersion

| | |
|-|-|
| Type | string |
| Required | yes |
| Valid values | `constle.dev/v1alpha1` |
| Enforcement | VALIDATED |

The schema version of this manifest. Must be exactly `constle.dev/v1alpha1`. The runtime
rejects any other value.

```yaml
apiVersion: constle.dev/v1alpha1
```

### kind

| | |
|-|-|
| Type | string |
| Required | yes |
| Valid values | `AgentManifest` |
| Enforcement | VALIDATED |

The resource type. Must be exactly `AgentManifest`. Reserved for future types such as
`AgentPolicy`.

```yaml
kind: AgentManifest
```

---

## Section: identity

Who this agent is. Used for logging and attribution.

```yaml
identity:
  name: "invoice-processor"
  version: "1.2.0"
  owner: "finance@company.com"
```

### identity.name

| | |
|-|-|
| Type | string |
| Required | yes |
| Enforcement | VALIDATED — appears in every audit log entry |

Human-readable name for this agent. Used as the identifier in `constle ps`, `constle stop`, and
all audit log entries. Must be non-empty. Recommended format: lowercase with hyphens.

### identity.version

| | |
|-|-|
| Type | string |
| Required | optional |
| Recommended format | semver, e.g. `1.0.0` |
| Enforcement | DECLARED |

The version of this agent. Useful for debugging and reconstructing what version of the agent
ran during an incident.

### identity.owner

| | |
|-|-|
| Type | string |
| Required | optional |
| Enforcement | DECLARED |

Email or identifier of the human responsible for this agent. Written to every audit log entry.
If absent, audit events record the owner as `"unknown"`.

Why this matters: in a compliance review or security incident, `owner` is what tells you which
human authorized this agent to run. Without it, attribution is impossible.

---

## Section: sandbox

How Constle runs and isolates the agent.

```yaml
sandbox:
  isolation: network
  image: "python:3.11-slim"
  command: ["python", "agent.py"]
  memory_mb: 512
  disk_mb: 2048
  network:
    egress: restricted
    allowed_hosts:
      - "api.groq.com"
```

### sandbox.isolation

| | |
|-|-|
| Type | string |
| Required | optional |
| Valid values | `none`, `process`, `network`, `kernel` |
| Default | auto-inferred from `capabilities` if not set |
| Enforcement | VALIDATED at parse time; backend selection is ENFORCED |

The isolation level required for this agent. If omitted, the runtime infers the minimum
necessary level from the `capabilities` list. If set explicitly, the runtime selects the
strongest available backend that satisfies this requirement.

**Isolation levels, from weakest to strongest:**

| Level | What it provides | Use when |
|-------|-----------------|----------|
| `none` | No isolation. Dev mode only. Never use in production. | Local testing only |
| `process` | Process-level separation from the host | Agent only reads or writes local files |
| `network` | Network and process isolation | Agent makes outbound API calls |
| `kernel` | Full hardware-level isolation via Firecracker microVM | Agent can transfer money, delete records, or spawn sub-agents |

The runtime always selects the highest required isolation level. If your capabilities list
includes `external_transfer`, the runtime requires `kernel` even if you declare
`isolation: process`.

### sandbox.image

| | |
|-|-|
| Type | string |
| Required | required in practice for the Docker backend |
| Enforcement | ENFORCED |

The Docker image to run. The runtime pulls this image and uses it as the agent's execution
environment.

```yaml
image: "python:3.11-slim"
image: "ghcr.io/myorg/myagent:v1.2.0"
```

### sandbox.command

| | |
|-|-|
| Type | list of strings |
| Required | optional |
| Enforcement | ENFORCED |

The command to run inside the container. Passed directly as the Docker CMD. If omitted, the
image's default CMD is used.

```yaml
command: ["python", "agent.py"]
command: ["node", "dist/index.js", "--task", "summarize"]
```

### sandbox.memory_mb

| | |
|-|-|
| Type | integer |
| Required | optional |
| Default | `512` |
| Unit | Megabytes |
| Enforcement | ENFORCED — passed as `--memory` to Docker |

Maximum RAM the container may use. Docker enforces this as a hard limit. The container is
killed with an out-of-memory error if it exceeds it.

### sandbox.disk_mb

| | |
|-|-|
| Type | integer |
| Required | optional |
| Default | `2048` |
| Unit | Megabytes |
| Enforcement | DECLARED |

Maximum disk space for the container's writable layer. Parsed and logged but not yet applied
to the Docker backend.

---

## Section: sandbox.network

Controls what the agent is allowed to reach on the network. This is the most security-critical
part of the manifest in v0.4.

```yaml
sandbox:
  network:
    egress: restricted
    allowed_hosts:
      - "api.openai.com"
      - "arxiv.org"
```

### sandbox.network.egress

| | |
|-|-|
| Type | string |
| Required | optional |
| Valid values | `restricted`, `open`, `none` |
| Default | `restricted` |
| Enforcement | ENFORCED |

Controls outbound network access from the agent container.

| Value | Effect |
|-------|--------|
| `restricted` | Agent can only reach hosts listed in `allowed_hosts`. All other outbound traffic is blocked at the network level. |
| `open` | Agent has unrestricted outbound internet access. Use with extreme caution. |
| `none` | Agent has no network access at all. |

How `restricted` is enforced: Constle connects the agent container only to an internal Docker
network that has no default gateway. A Squid proxy container is the only bridge to the
internet, and it enforces the allowlist. This is enforced at the OS network level. The agent
cannot bypass it by unsetting environment variables or attempting direct IP connections.

### sandbox.network.allowed_hosts

| | |
|-|-|
| Type | list of strings |
| Required | required when `egress: restricted` |
| Enforcement | ENFORCED |

Hostnames the agent is permitted to reach. Domain names only. No ports, no wildcards, no IP
addresses in this version.

```yaml
allowed_hosts:
  - "api.groq.com"
  - "api.openai.com"
```

All outbound connections to hosts not on this list are blocked and logged to the audit trail
as `network_blocked` events.

---

## Section: capabilities

An explicit list of what the agent is allowed to do. The runtime uses this list to infer the
minimum required isolation level if `sandbox.isolation` is not set.

```yaml
capabilities:
  - web_search
  - external_api
  - read_file
```

### Capability values

| Value | Meaning | Minimum isolation required |
|-------|---------|--------------------------|
| `read_file` | Read files from the filesystem | `process` |
| `write_file` | Write files to the filesystem | `process` |
| `web_search` | Make outbound HTTP requests for search | `network` |
| `external_api` | Call external APIs over the network | `network` |
| `send_email` | Send email via external SMTP or API | `network` |
| `spawn_subagent` | Start another agent as a subprocess | `kernel` |
| `external_transfer` | Transfer money or financial assets | `kernel` |
| `delete_records` | Permanently delete data | `kernel` |

The runtime selects the highest minimum isolation level across all declared capabilities.

Example: an agent with `[web_search, external_transfer]` requires `kernel` isolation,
because `external_transfer` requires it.

Current enforcement status: capabilities influence isolation level selection and are written to
the audit log at run start. Enforcement of individual capabilities (blocking an undeclared
action mid-run) is planned for v0.5.

---

## Section: spending

Budget limits for what the agent is allowed to spend per run, per day, and per month.

```yaml
spending:
  max_per_run_usd: "0.50"
  max_per_day_usd: "5.00"
  max_per_month_usd: "50.00"
```

All three fields are DECLARED in v0.4. The runtime parses them and writes them to the audit
log at run start, but it does not track actual costs or stop the agent when limits are reached.
Enforcement is planned for v0.5.

### spending.max_per_run_usd

| | |
|-|-|
| Type | string (decimal number) |
| Required | optional |
| Enforcement | DECLARED |

Maximum cost in USD for a single agent run. When enforcement is implemented, the runtime
will abort the run and log a `spending_limit_exceeded` event if this value is reached.

### spending.max_per_day_usd

| | |
|-|-|
| Type | string (decimal number) |
| Required | optional |
| Enforcement | DECLARED |

Maximum cumulative spend across all runs of this agent in a calendar day (UTC).

### spending.max_per_month_usd

| | |
|-|-|
| Type | string (decimal number) |
| Required | optional |
| Enforcement | DECLARED |

Maximum cumulative spend across all runs of this agent in a calendar month (UTC).

---

## Section: limits

Hard execution constraints that the runtime enforces actively today. Unlike `spending`, the
fields in this section are ENFORCED in v0.4.

The `spending` and `limits` sections are intentionally separate. `limits` contains what the
runtime acts on now. `spending` contains what will be enforced in a future version. The
separation makes it immediately clear what you can rely on.

```yaml
limits:
  max_duration_seconds: 300
```

### limits.max_duration_seconds

| | |
|-|-|
| Type | integer |
| Required | optional |
| Default | `0` (no limit) |
| Unit | seconds |
| Enforcement | ENFORCED |

Maximum wall-clock time the agent is allowed to run. When the limit is reached, the runtime
sends `docker stop` to the container and writes a `terminated_by_limit` event to the audit log.

A value of `0` means no time limit is applied.

```yaml
limits:
  max_duration_seconds: 300   # 5 minutes
```

---

## Section: human_gates

Defines when the agent must pause and wait for human approval before continuing. Human gates
are the primary defense against prompt injection attacks that try to trick the agent into
performing a sensitive action.

```yaml
human_gates:
  enabled: true
  require_approval_for:
    - external_transfer
    - delete_records
    - send_email
  on_timeout: abort
```

All fields in this section are DECLARED in v0.4. The runtime parses and logs them, but does
not yet pause execution to wait for approval. Full enforcement is planned for v1.0.

### human_gates.enabled

| | |
|-|-|
| Type | boolean |
| Required | optional |
| Default | `false` |
| Enforcement | DECLARED |

Master switch for human gate enforcement. When `true`, the actions listed in
`require_approval_for` will require human approval before the agent executes them.

Set to `false` only for fully automated, low-risk agents where human review adds no value.

### human_gates.require_approval_for

| | |
|-|-|
| Type | list of strings |
| Required | optional |
| Enforcement | DECLARED |

The action categories that require human approval. Recommended values correspond to the
high-risk entries in `capabilities`: `external_transfer`, `delete_records`, `send_email`,
`spawn_subagent`.

### human_gates.on_timeout

| | |
|-|-|
| Type | string |
| Required | optional |
| Valid values | `abort`, `proceed` |
| Default | `abort` |
| Enforcement | DECLARED |

What the runtime does when a human gate triggers but no approval arrives within the timeout
period.

| Value | Behavior |
|-------|----------|
| `abort` | The agent run is terminated. The pending action is not taken. This is the safe default. |
| `proceed` | The agent continues without approval. Use only for low-risk gates where availability matters more than confirmation. |

Use `abort`. An agent that proceeds without human approval after a timeout defeats the purpose
of the gate.

---

## Section: compliance

Audit logging configuration and regulatory declarations.

```yaml
compliance:
  audit_log_level: standard
  frameworks:
    - EU_AI_ACT
    - SOC2_TYPE2
  geo_restrictions:
    allowed_regions:
      - eu-west-1
      - eu-central-1
    denied_regions: []
```

### compliance.audit_log_level

| | |
|-|-|
| Type | string |
| Required | optional |
| Valid values | `none`, `minimal`, `standard`, `verbose` |
| Default | `standard` |
| Enforcement | ENFORCED |

Controls what the runtime writes to the JSONL audit log at `~/.constle/logs/`.

| Level | Events logged |
|-------|--------------|
| `none` | No audit log is written |
| `minimal` | Run start, run end, errors only |
| `standard` | Start, end, network events, limit events, spending events |
| `verbose` | All of the above plus every agent action and tool call |

### compliance.frameworks

| | |
|-|-|
| Type | list of strings |
| Required | optional |
| Enforcement | DECLARED |

Regulatory frameworks this agent deployment must satisfy. Written to audit log metadata.
Compliance report generation from these declarations is planned for v1.0.

Common values: `EU_AI_ACT`, `SOC2_TYPE2`, `ISO27001`, `HIPAA`, `PCI_DSS`.

### compliance.geo_restrictions.allowed_regions

| | |
|-|-|
| Type | list of strings |
| Required | optional |
| Enforcement | DECLARED |

Cloud region identifiers where this agent is permitted to run. An empty list means no
geographic restriction. Example: `["eu-west-1", "eu-central-1"]` for a GDPR EU-only deployment.

### compliance.geo_restrictions.denied_regions

| | |
|-|-|
| Type | list of strings |
| Required | optional |
| Enforcement | DECLARED |

Cloud region identifiers where this agent must not run. Takes precedence over
`allowed_regions` if a region appears in both lists.

---

## Section: metadata

Informational fields for humans and external tooling. The runtime does not use any of these
fields when making execution decisions.

```yaml
metadata:
  description: "Processes invoices and routes to approval queue."
  author: "finance-team@company.com"
  license: "Apache-2.0"
  labels:
    team: "finance"
    cost_center: "cc-1042"
    environment: "production"
```

### metadata.description

Human-readable description of what this agent does. INFORMATIONAL.

### metadata.author

Identifier of the author. Can be an email address, DID, or GitHub handle. INFORMATIONAL.

### metadata.license

SPDX license identifier for the agent's code. Examples: `Apache-2.0`, `MIT`. INFORMATIONAL.

### metadata.labels

Arbitrary key-value string pairs for organizational use. Useful for cost allocation, team
ownership, and environment tagging. No enforced key names or value formats. INFORMATIONAL.

---

## Enforcement Summary

| Field | Enforcement | Notes |
|-------|-------------|-------|
| `apiVersion` | VALIDATED | Must be `constle.dev/v1alpha1` |
| `kind` | VALIDATED | Must be `AgentManifest` |
| `identity.name` | VALIDATED | Must be non-empty; appears in all audit events |
| `identity.version` | DECLARED | Logged at run start |
| `identity.owner` | DECLARED | Logged at run start; `"unknown"` if absent |
| `sandbox.isolation` | VALIDATED | Inferred if absent; drives backend selection |
| `sandbox.image` | ENFORCED | Docker pulls and runs this image |
| `sandbox.command` | ENFORCED | Passed as Docker CMD |
| `sandbox.memory_mb` | ENFORCED | Passed as `--memory` to Docker |
| `sandbox.disk_mb` | DECLARED | Parsed but not yet applied |
| `sandbox.network.egress` | ENFORCED | Two-network Docker architecture with Squid proxy |
| `sandbox.network.allowed_hosts` | ENFORCED | Squid proxy allowlist |
| `capabilities` | DECLARED | Influences isolation inference; logged at run start |
| `spending.max_per_run_usd` | DECLARED | Logged; not tracked or enforced yet |
| `spending.max_per_day_usd` | DECLARED | Logged; not tracked or enforced yet |
| `spending.max_per_month_usd` | DECLARED | Logged; not tracked or enforced yet |
| `limits.max_duration_seconds` | ENFORCED | Container killed after this; audit event written |
| `human_gates.enabled` | DECLARED | Logged; gate not triggered at runtime yet |
| `human_gates.require_approval_for` | DECLARED | Logged; not checked at runtime yet |
| `human_gates.on_timeout` | DECLARED | Logged; not applied yet |
| `compliance.audit_log_level` | ENFORCED | Controls what the runtime logs |
| `compliance.frameworks` | DECLARED | Logged in audit metadata |
| `compliance.geo_restrictions` | DECLARED | Not checked at runtime |
| `metadata.*` | INFORMATIONAL | Not read by runtime |

---

## Examples

### Minimal Example

The smallest valid Agentfile that is actually useful:

```yaml
apiVersion: constle.dev/v1alpha1
kind: AgentManifest

identity:
  name: "my-agent"

sandbox:
  image: "python:3.11-slim"
  command: ["python", "agent.py"]
  network:
    egress: restricted
    allowed_hosts:
      - "api.openai.com"
```

This manifest runs `python agent.py` in a Python 3.11 container, blocks all network traffic
except to `api.openai.com`, applies no time limit, and logs at the default `standard` level.

---

### Full Example

A production-grade manifest for a financial processing agent:

```yaml
apiVersion: constle.dev/v1alpha1
kind: AgentManifest

identity:
  name: "invoice-processor"
  version: "2.1.0"
  owner: "finance-team@company.com"

sandbox:
  isolation: kernel
  image: "ghcr.io/myorg/invoice-agent:2.1.0"
  command: ["python", "main.py"]
  memory_mb: 1024
  disk_mb: 4096
  network:
    egress: restricted
    allowed_hosts:
      - "api.openai.com"
      - "api.company-erp.com"

capabilities:
  - read_file
  - write_file
  - external_api
  - external_transfer

spending:
  max_per_run_usd: "0.50"
  max_per_day_usd: "10.00"
  max_per_month_usd: "150.00"

limits:
  max_duration_seconds: 300

human_gates:
  enabled: true
  require_approval_for:
    - external_transfer
    - delete_records
  on_timeout: abort

compliance:
  audit_log_level: verbose
  frameworks:
    - EU_AI_ACT
    - SOC2_TYPE2
  geo_restrictions:
    allowed_regions:
      - eu-west-1
      - eu-central-1
    denied_regions: []

metadata:
  description: >
    Reads incoming invoices, validates them against the ERP,
    and initiates payment transfers. Human approval is required
    before every transfer.
  author: "finance-team@company.com"
  license: "Proprietary"
  labels:
    team: "finance"
    cost_center: "cc-1042"
    environment: "production"
    sensitivity: "high"
```

---

## Versioning and Breaking Changes

### Current Version

This specification is at `v1alpha1`. This means field names and semantics may change between
releases before v1.0. No compatibility guarantees are made in this phase.

### How apiVersion Changes

When a breaking change is introduced, the `apiVersion` value is bumped:

| apiVersion | Status | Meaning |
|------------|--------|---------|
| `constle.dev/v1alpha1` | Current | Unstable. In active development. |
| `constle.dev/v1beta1` | Planned | Stable field names. New fields may be added. |
| `constle.dev/v1` | Planned | Fully stable. Backward-compatible changes only. |

The runtime will support the previous `apiVersion` for at least one major release after it is
deprecated. A `v1beta1` runtime will run `v1alpha1` manifests and write a deprecation warning
to the audit log.

### What Is a Breaking Change

A breaking change is anything that causes a previously valid manifest to be rejected or to
behave differently without modification:

- Renaming a field
- Changing the type of a field (e.g. integer to string)
- Making an optional field required
- Removing a valid enum value
- Changing the default value of a field in a way that affects security behavior

### What Is Not a Breaking Change

- Adding a new optional field
- Adding a new valid enum value
- Adding a new section that is entirely optional
- Moving a field from DECLARED to ENFORCED — this is always a feature, not a breaking change

### Changelog

#### 0.1.0-draft (current)

- Initial draft of the AgentManifest specification
- Defined `identity`, `sandbox`, `capabilities`, `spending`, `limits`, `human_gates`,
  `compliance`, `metadata` sections
- `limits.max_duration_seconds`, `sandbox.network`, and `sandbox.memory_mb` are ENFORCED
- All `spending` and `human_gates` fields are DECLARED, not yet ENFORCED

---

## Field Quick Reference

| Field | Type | Required | Default | Enforcement |
|-------|------|----------|---------|-------------|
| `apiVersion` | string | yes | — | VALIDATED |
| `kind` | string | yes | — | VALIDATED |
| `identity.name` | string | yes | — | VALIDATED |
| `identity.version` | string | no | — | DECLARED |
| `identity.owner` | string | no | — | DECLARED |
| `sandbox.isolation` | string | no | auto | VALIDATED |
| `sandbox.image` | string | no* | — | ENFORCED |
| `sandbox.command` | []string | no | image CMD | ENFORCED |
| `sandbox.memory_mb` | int | no | 512 | ENFORCED |
| `sandbox.disk_mb` | int | no | 2048 | DECLARED |
| `sandbox.network.egress` | string | no | restricted | ENFORCED |
| `sandbox.network.allowed_hosts` | []string | no** | — | ENFORCED |
| `capabilities` | []string | no | — | DECLARED |
| `spending.max_per_run_usd` | string | no | — | DECLARED |
| `spending.max_per_day_usd` | string | no | — | DECLARED |
| `spending.max_per_month_usd` | string | no | — | DECLARED |
| `limits.max_duration_seconds` | int | no | 0 (none) | ENFORCED |
| `human_gates.enabled` | bool | no | false | DECLARED |
| `human_gates.require_approval_for` | []string | no | — | DECLARED |
| `human_gates.on_timeout` | string | no | abort | DECLARED |
| `compliance.audit_log_level` | string | no | standard | ENFORCED |
| `compliance.frameworks` | []string | no | — | DECLARED |
| `compliance.geo_restrictions.allowed_regions` | []string | no | — | DECLARED |
| `compliance.geo_restrictions.denied_regions` | []string | no | — | DECLARED |
| `metadata.description` | string | no | — | INFORMATIONAL |
| `metadata.author` | string | no | — | INFORMATIONAL |
| `metadata.license` | string | no | — | INFORMATIONAL |
| `metadata.labels` | map[string]string | no | — | INFORMATIONAL |

*`sandbox.image` is required in practice for the Docker backend.
**`sandbox.network.allowed_hosts` is required when `egress: restricted`.
