# Constle Roadmap

This document tracks the planned milestones from the initial spec draft to a production-ready v1.0 runtime.

Milestones are not time-boxed — they ship when they are ready. Each milestone's scope is intentionally narrow so that the project ships working software at every step rather than accumulating half-finished features.

**Legend:** `done` · `in progress` · `planned` · `stretch`

---

## v0.1 — Foundation `in progress`

_Goal: a repo people can read, fork, and orient around._

- [x] Agent Manifest spec v0.1-draft (`spec/agent-manifest.yaml`)
- [x] README with vision, pillars, and quickstart
- [x] CLI skeleton: `validate`, `run`, `inspect`, `logs`, `identity`, `registry` (stubs)
- [x] GitHub repo structure: CI workflow, issue templates, PR template, CODEOWNERS
- [x] CONTRIBUTING guide and ROADMAP
- [ ] `go.sum` and dependency lockfile committed
- [ ] Basic `constle validate` implemented (YAML parse + schema check, no sandbox)
- [ ] Published to `constle.dev`

---

## v0.2 — Local Run (No Sandbox) `planned`

_Goal: agents actually execute. No isolation yet — for local development only._

- [ ] `constle run --sandbox=none` executes the agent process directly
- [ ] Capability allowlist enforced at the MCP client layer (soft, process-level)
- [ ] Spending meter: track estimated cost per run, warn on threshold breach
- [ ] Human gate: terminal prompt blocks the run until the user approves or denies
- [ ] Structured audit log written to `~/.constle/logs/<run-id>.jsonl`
- [ ] `constle logs` reads and formats the audit log
- [ ] `constle inspect` shows live resource usage (via `/proc` or OS APIs)
- [ ] `constle diff <a.yaml> <b.yaml>` — compare two manifests field by field

---

## v0.3 — Firecracker Sandbox `planned`

_Goal: real isolation. Agents cannot escape their declared resource limits._

- [ ] Firecracker microVM provisioned from the Agent Manifest `sandbox` block
- [ ] CPU, memory, disk limits enforced at the hypervisor level
- [ ] Wall-clock timeout kills the VM
- [ ] Network egress filtered to `allowed_hosts` via in-VM iptables rules
- [ ] Filesystem mounts injected via virtio-fs
- [ ] Secrets injected at `/run/secrets` (never on disk at rest)
- [ ] `constle run --sandbox=firecracker` works end-to-end on Linux
- [ ] CI gate: sandbox integration tests run in a nested VM environment

---

## v0.4 — MCP Protocol Bridge `planned`

_Goal: agents can use tools declared in the manifest, nothing more._

- [ ] MCP server registry: map `capability.mcp[].id` to server URLs/binaries
- [ ] MCP proxy inside the sandbox intercepts all tool calls
- [ ] Undeclared tools are rejected with a structured error
- [ ] Tool-level allow/deny enforced (e.g., `read_file` yes, `delete_file` no)
- [ ] MCP session is audited: every tool call logged to the run's audit trail
- [ ] `constle validate` checks that declared MCP servers are reachable

---

## v0.5 — Identity & KYA `in progress`

_Goal: every agent has a verifiable identity; trust can be established and delegated._

- [x] `constle identity create` — generate Ed25519 key pair, emit a standard
      [did:key](https://w3c-ccg.github.io/did-method-key/) identifier (chosen over a custom
      `did:constle` method: the DID self-describes the public key, so verification needs no
      resolution service — see `spec/identity.md`)
- [x] Audit log signing: every entry Ed25519-signed and hash-chained when `identity.did`
      is declared; `constle audit verify` detects and localizes tampering
- [x] `constle run` fails closed when `identity.did` has no matching local private key
- [ ] Agent manifest signed at publish time; signature verified at `constle run`
- [ ] Parent/child DID chain: child agent inherits a subset of parent's capabilities
- [ ] KYA registry API (hosted at `constle.dev`): publish and resolve DID documents
- [ ] `constle registry push` submits manifest + signature to the registry
- [ ] `constle registry pull <did>` downloads and verifies a manifest

---

## v0.6 — Human Gates `planned`

_Goal: agents can be paused at defined checkpoints for human review._

- [ ] Gate conditions evaluated at runtime against the action stream
- [ ] Webhook delivery for gate events (JSON payload, retry with backoff)
- [ ] Gate resolution API: approve / deny / modify via HTTP
- [ ] `constle gate list <run-id>` — show pending gates for a run
- [ ] `constle gate approve <gate-id>` and `constle gate deny <gate-id>`
- [ ] Timeout policy enforced (`on_timeout: abort | proceed | retry`)
- [ ] Gate events included in the audit log

---

## v0.7 — Spending Enforcement (x402) `planned`

_Goal: agents cannot spend more than declared. Limits are enforced by the runtime, not trusted from the agent._

- [ ] x402 payment interceptor proxies all outbound HTTP from the sandbox
- [ ] Per-request cost estimated before the call is allowed through
- [ ] `max_per_run_usd` hard limit kills the run if exceeded
- [ ] `max_per_day_usd` tracked persistently across runs
- [ ] `require_human_approval_above_usd` triggers a human gate
- [ ] Spending ledger written to `~/.constle/spending.db` (SQLite)
- [ ] `constle spending report` — show spend by agent, day, and month
- [ ] Alert webhook fired at `warn_at_pct_of_daily` threshold

---

## v0.8 — A2A / ACP Protocols `planned`

_Goal: agents can talk to other agents within declared peer allowlists._

- [ ] A2A peer registry: resolve peer DIDs to endpoints
- [ ] Outbound A2A calls validated against `capabilities.peers[]`
- [ ] `max_calls_per_run` enforced per peer
- [ ] ACP message envelope: structured request/response with schema validation
- [ ] Inbound A2A: agent can be called as a peer by other Constle agents
- [ ] Peer-to-peer spending propagation: child agent spend counted against parent budget
- [ ] `constle inspect` shows active peer connections

---

## v0.9 — gVisor Backend & Multi-Platform `planned`

_Goal: Constle runs everywhere — Linux servers, macOS dev machines, CI, and cloud._

- [ ] gVisor (`runsc`) backend for environments where Firecracker is unavailable
- [ ] macOS support via gVisor or lightweight container runtime (dev mode)
- [ ] Windows support: `--sandbox=none` for development; gVisor via WSL2
- [ ] ARM64 builds (Apple Silicon, Graviton)
- [ ] Helm chart for Kubernetes deployment of the Constle runtime daemon
- [ ] `constle daemon` — persistent runtime daemon with HTTP management API
- [ ] Pre-built binaries published via GoReleaser on every tag

---

## v1.0 — Production Ready `planned`

_Goal: stable public API, hardened runtime, documented threat model._

- [ ] Agent Manifest spec promoted from `v1alpha1` to `v1` (no further breaking changes without a major version bump)
- [ ] CLI commands and flags frozen (semver-stable)
- [ ] Threat model document published: what Constle protects against and what it does not
- [ ] Security audit of the sandbox escape surface
- [ ] End-to-end conformance test suite: any compliant runtime must pass
- [ ] Agent registry GA at `constle.dev/registry`
- [ ] Operator guide: running Constle in production (auth, networking, monitoring)
- [ ] SDK bindings: Python, TypeScript (for embedding the runtime or building agents)

---

## Stretch Goals (post-v1.0)

These are on the radar but not yet scheduled:

- **Wasm backend** — ultra-lightweight sandbox for edge/embedded environments
- **TEE attestation** — hardware-rooted trust for high-assurance deployments (AMD SEV, Intel TDX)
- **Agent marketplace** — browse, purchase, and deploy community agents from the registry
- **Policy engine** — OPA/Rego-based policy evaluation for enterprise governance
- **Multi-agent orchestration** — first-class support for agent DAGs and pipelines
- **Compliance packs** — pre-built manifest templates for HIPAA, PCI-DSS, FedRAMP

---

## How to Influence the Roadmap

Open an [RFC issue](https://github.com/constle/constle/issues/new?template=rfc.md) to propose moving something up, adding something new, or splitting a milestone differently. The roadmap is a living document — PRs to this file are welcome.
