# Constle

**The open enforcement standard for AI agents.**

Constle is the runtime layer between your infrastructure and your AI agents — enforcing network isolation, spending limits, max duration, and audit logging for every agent, regardless of which framework built it or which cloud it runs on.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go 1.22+](https://img.shields.io/badge/go-1.22+-00ADD8.svg)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/constle/constle)](https://github.com/constle/constle/releases)
[![Build](https://github.com/constle/constle/actions/workflows/release.yml/badge.svg)](https://github.com/constle/constle/actions)

```bash
curl -fsSL https://constle.dev/install | sh
constle run agent.yaml
```

---

## The Problem

AI agents are autonomous software: they browse the web, call APIs, write files, and transfer funds — without human approval at each step. That's what makes them useful. It's also what makes deployments go wrong.

Most teams building agents today answer these questions differently — or not at all:

- How do I ensure this agent can't reach data outside its task scope?
- How do I enforce a spending limit the agent itself can't bypass?
- How do I prove to a security team that every action was logged?
- What happens if the agent reads a malicious document and acts on it?

The result is bespoke, fragile security stitched together per agent — and most pilots never reach production.

**Constle is a single open standard that answers all of these at the runtime level.** Not in the agent's code, which can be compromised — in the environment the agent runs inside.

---

## What Constle Enforces

| Enforcement Layer | What It Does | Status |
|---|---|---|
| **Network isolation** | Agent container has no default gateway. All egress must pass through a proxy that only allows declared hosts. Bypass is architecturally impossible. | ✅ v0.4 |
| **Max duration** | Agent is forcibly stopped after `max_duration_seconds`. Not a suggestion — the runtime kills it. | ✅ v0.4 |
| **Audit log** | Every agent run produces a signed JSONL log of actions and network events at `~/.constle/logs/`. | ✅ v0.4 |
| **Spending limits** | Hard cap per run and per day enforced by the runtime. Agent code cannot exceed them regardless of instructions. | 🔨 v0.5 |
| **Human gate policies** | Sensitive actions (transfers, deletions, external comms) pause and require human approval before proceeding. | 🔨 v0.5 |
| **Cryptographic identity** | Every agent gets a W3C DID anchored to a human owner. Every action is signed and attributable. | 🔨 v0.5 |

Constle is **not** a framework. It does not tell agents how to think or plan. LangGraph, CrewAI, OpenAI Agents SDK, or any other framework run inside Constle unchanged.

---

## Quick Start

### Install

**Linux / macOS:**
```bash
curl -fsSL https://constle.dev/install | sh
```

**Windows (PowerShell):**
```powershell
irm https://constle.dev/install.ps1 | iex
```

**From source (Go 1.22+):**
```bash
git clone https://github.com/constle/constle
cd constle
go build -o constle ./cmd/constle
```

Pre-built binaries for Linux, macOS, and Windows (amd64 + arm64) are available on the [releases page](https://github.com/constle/constle/releases).

### Write an AgentManifest

Create `agent.yaml`:

```yaml
apiVersion: constle.dev/v1alpha1
kind: AgentManifest

identity:
  name: my-agent
  owner: you@company.com

sandbox:
  backend: docker
  memory_mb: 512
  network:
    mode: restricted
    allowed:
      - api.openai.com
      - api.anthropic.com
  docker:
    image: "my-agent:latest"

spending:
  max_per_run_usd: 0.50
  max_per_day_usd: 5.00

limits:
  max_duration_seconds: 300
```

### Run

```bash
constle validate agent.yaml          # validate the manifest before running
constle run agent.yaml               # run the agent in an isolated sandbox
constle ps                           # list all running agents
constle stop <run-id>                # stop a specific agent by ID
```

---

## The AgentManifest

The AgentManifest (`agent.yaml`) is Constle's portable, declarative agent descriptor — a YAML file specifying everything the runtime needs to enforce policy around an agent. Write it once; Constle enforces it identically on AWS, GCP, Azure, or bare metal.

```yaml
apiVersion: constle.dev/v1alpha1
kind: AgentManifest

identity:
  did: did:constle:z6Mk...4doK      # cryptographic identity (v0.5)
  name: invoice-processor
  owner: finance@company.com

sandbox:
  backend: docker                  # firecracker in v0.5
  memory_mb: 512
  network:
    mode: restricted
    allowed:
      - api.accounting.internal
      - api.openai.com
  docker:
    image: "invoice-agent:1.2.0"

capabilities:
  mcp_servers:
    - name: accounting-api
    - name: document-reader

spending:
  max_per_run_usd: 0.50           # enforced by runtime, not agent code
  max_per_day_usd: 5.00

limits:
  max_duration_seconds: 300

human_gates:
  enabled: true                   # (v0.5)
  triggers:
    - action: external_transfer
    - action: delete_records
  on_timeout: abort               # safe default — stop, never proceed

compliance:
  audit_log: tamper_evident
  frameworks:
    - EU_AI_ACT
    - SOC2_TYPE_II
```

Every field in the spec is labeled **ENFORCED**, **DECLARED**, **VALIDATED**, or **INFORMATIONAL** — clearly documenting what the current runtime actually prevents vs. what is parsed for future enforcement or logging. See [`spec/agent-manifest.md`](spec/agent-manifest.md).

---

## Architecture

Constle is organized into four layers, each addressing a distinct category of the agent governance problem:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 4 — Commerce & Marketplace                  (v2.0)  │
│  Open agent registry · x402 micropayments · Agent hiring   │
├─────────────────────────────────────────────────────────────┤
│  Layer 3 — Communication & Interoperability        (v1.0)  │
│  MCP for tools · A2A for agents · ACP for interop          │
├─────────────────────────────────────────────────────────────┤
│  Layer 2 — Identity & Governance                   (v0.5)  │
│  W3C DID · Ed25519 · Human gates · Spending limits         │
├─────────────────────────────────────────────────────────────┤
│  Layer 1 — Secure Runtime & Sandbox                (v0.4)  │  ← now
│  Docker sandbox · Network isolation · Audit log            │
└─────────────────────────────────────────────────────────────┘
```

Layer 1 is fully shipped. Each subsequent layer builds on it without breaking the AgentManifest format — manifests written today will work in v0.5 and beyond.

### How Network Isolation Works

Constle uses a two-network Docker architecture that makes egress restriction bypass-proof:

```
[Agent Container]
      │ (constle-internal network — no default gateway)
      ▼
[Squid Proxy]  ←  only forwards traffic to declared hosts
      │ (constle-external network — has internet access)
      ▼
[Declared hosts: api.openai.com, ...]
```

The agent container has **no default gateway**. It cannot reach the internet directly, regardless of what the agent is instructed to do. All egress passes through a proxy that enforces the `network.allowed` list from the AgentManifest.

This means a successful prompt injection — where malicious content inside a document tricks the agent into trying to exfiltrate data — physically cannot send data to an undeclared destination. The network layer stops it, not the model.

---

## Try the Demo Agent

`examples/basic-agent/` contains a working agent built with Python and Groq's free API tier:

```bash
# Get a free API key at console.groq.com
export GROQ_API_KEY=your_key_here

constle run examples/basic-agent/agent.yaml
```

The demo runs Llama 3 via Groq, inside a network-restricted Docker sandbox, with a full audit log written to `~/.constle/logs/`.

---

## CLI Reference

| Command | Description |
|---|---|
| `constle run <manifest>` | Run an agent in an isolated sandbox |
| `constle validate <manifest>` | Validate an AgentManifest without running |
| `constle ps` | List all Constle-managed agents currently running |
| `constle stop <run-id>` | Stop a running agent by its run ID |
| `constle init` | Create a starter AgentManifest in the current directory |

---

## What Constle Is Not

**Not an agent framework.** Constle does not define how agents reason, plan, or use tools. LangGraph, CrewAI, and every other framework work inside Constle unchanged. Constle governs the environment, not the logic.

**Not a cloud provider.** Constle installs on your infrastructure — any cloud or on-premise. It is software, not servers. The same AgentManifest runs identically on AWS, GCP, Azure, or a local machine.

**Not a monitoring overlay.** Monitoring detects problems after the fact. Constle prevents them by construction: network isolation stops data exfiltration even if the model is compromised, because the network layer is enforced below the agent, not inside it.

**Not a closed platform.** Apache 2.0. The AgentManifest format is an open standard, independently auditable, with no vendor dependency.

---

## Roadmap

| Version | Status | Highlights |
|---|---|---|
| **v0.4** | ✅ Released | Docker sandbox, network isolation, audit log, `constle ps/stop`, demo agent |
| **v0.5** | 🔨 In progress | Firecracker microVM (kernel-level isolation), W3C DID identity, spending enforcement, human gates |
| **v1.0** | Planned | Web dashboard, webhook-based human gates, enterprise beta |
| **v1.5** | Planned | Constle Cloud (hosted), compliance reports, agent registry |
| **v2.0** | Planned | Open marketplace, x402 agent-to-agent payments |

---

## Repository Structure

```
constle/
├── cmd/constle/          # CLI entry point (main.go, ps.go, stop.go)
├── internal/
│   ├── audit/          # JSONL audit logger + Squid log parser
│   └── sandbox/        # SandboxBackend interface + Docker implementation
├── pkg/manifest/       # AgentManifest types and YAML parser
├── examples/
│   └── basic-agent/    # Working demo agent (Python + Groq)
└── spec/
    └── agent-manifest.md  # Full AgentManifest specification
```

---

## Contributing

Constle is early and moving fast. Contributions are welcome, especially:

- Bug reports and edge cases in the sandbox
- AgentManifest parser improvements
- New sandbox backend implementations (gVisor, Firecracker)
- Documentation and more example agents

See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

---

## License

[Apache 2.0](LICENSE)

---

**[constle.dev](https://constle.dev) · [github.com/constle](https://github.com/constle) · [hello@constle.dev](mailto:hello@constle.dev)**
