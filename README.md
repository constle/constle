# Constle

**An open enforcement standard for AI agents.**

Constle sits between your infrastructure and your agent's code. It doesn't ask an agent to behave - it makes certain things physically impossible, and cuts the run the moment a declared limit is crossed, no matter what the agent was told to do.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go 1.26+](https://img.shields.io/badge/go-1.26+-00ADD8.svg)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/constle/constle)](https://github.com/constle/constle/releases)
[![Build](https://github.com/constle/constle/actions/workflows/release.yaml/badge.svg)](https://github.com/constle/constle/actions)


```
$ constle run invoice-processor.yaml
...
constle: spending limit reached (max_per_run_usd) - stopping agent...
⚑ agent terminated: spending limit (max_per_run_usd) exceeded    run_spend=$0.52    duration=41s
  audit log: ~/.constle/logs/2026-07-26-invoice-processor.jsonl
```

The agent didn't choose to stop. The runtime stopped it, at the exact moment the ledger crossed the cap declared in the manifest - regardless of what the agent's own code, prompt, or model output said to do next.

---

## Why this exists

An agent that reads email, calls APIs, or moves money is running code you didn't fully audit, on inputs you don't control. By default it inherits every permission the process around it has: every file, every credential, unlimited spend on any connected account. If a document it reads contains a hidden instruction, it has no way to know that - following instructions is the whole job.

Constle exists to make four things true regardless of what the agent decides to do:

- It can't reach a host you didn't declare.
- It can't spend past a cap you set, even mid-run.
- A sensitive action pauses for a human, and defaults to *not happening* if nobody answers.
- Every action it took is in a signed log you can hand to an auditor.

---

## What Constle enforces

| Layer | What it enforces | Status |
|---|---|---|
| **Sandboxed execution** | Every agent runs in a Firecracker microVM (hardware-level isolation) or a two-network Docker sandbox with no default gateway. All egress passes through an allowlisting proxy. Backend is auto-detected or set with `--backend`. | Shipped |
| **Max duration** | The agent is killed when `max_duration_seconds` elapses. | Shipped |
| **Audit log** | Every run writes a JSONL audit log. When `identity.did` is set, every entry is Ed25519-signed and hash-chained; `constle audit verify` detects and localizes tampering. | Shipped |
| **Spending limits** | Hard per-run and per-day USD caps. Cost is metered at the MCP gate proxy against each server's declared pricing; the daily ledger is a durable, per-agent record that persists across runs. | Shipped |
| **Human gate policies** | Declared MCP servers are reachable only through a protocol-aware gate proxy. A call matching `human_gates.require_approval_for` pauses for approval; on timeout, the default is abort, not proceed. | Shipped |
| **Cryptographic identity** | A W3C `did:key` identity (Ed25519) binds an agent to a human owner and signs its audit trail. `constle run` fails closed if a declared DID has no matching local key. | Shipped |
| **Agent-to-agent messaging** | Agents exchange signed messages with declared peers only; anything outside the allowlist is rejected before it's sent. | Shipped |

Constle is **not** a framework - it doesn't decide how an agent reasons or plans. LangGraph, CrewAI, or hand-rolled code all run inside Constle unchanged.

Here's the same enforcement on the approval side - an agent tries something the manifest requires a human to sign off on, nobody answers in time:

```
constle: human gate timed out (on_timeout: abort) - stopping agent...
⚑ agent terminated: human gate timed out without approval (on_timeout: abort)    duration=312s
  audit log: ~/.constle/logs/2026-07-26-invoice-processor.jsonl
```

No approval, no action. That's the default, not a configuration you have to remember to set.

---

## Quick start

### Install

```bash
git clone https://github.com/constle/constle
cd constle
go build -o constle ./cmd/constle
```

Requires Go 1.26+. Pre-built binaries for Linux, macOS, and Windows are on the [releases page](https://github.com/constle/constle/releases).

### Verify your download

Every release ships a `checksums.txt` covering all six archives, signed with
[cosign](https://docs.sigstore.dev/) keyless signing from the release workflow.
Download `checksums.txt`, `checksums.txt.sig`, and `checksums.txt.pem` from the
release page next to your archive, then:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/constle/constle/\.github/workflows/release\.yaml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
```

Expect `Verified OK`. Then check your archive against the now-trusted checksum file:

```bash
sha256sum --check --ignore-missing checksums.txt
```

The two `--certificate-*` flags are **not optional**. Keyless signing has no
fixed public key: anyone can obtain a valid Fulcio certificate and sign
anything. What makes the signature mean something is *which identity* it binds
to. Without `--certificate-identity-regexp` and `--certificate-oidc-issuer`,
cosign will happily report `Verified OK` for a file signed by a complete
stranger - all it proves is that *somebody* signed it. Pinning the identity to
`constle/constle`'s `release.yaml` on a `v*` tag, issued by GitHub's OIDC
issuer, is what turns that into "this came from the Constle release workflow."

Each archive additionally carries a SLSA build-provenance attestation:

```bash
gh attestation verify constle_0.5.0_linux_amd64.tar.gz --repo constle/constle
```

### Write an AgentManifest

```yaml
apiVersion: constle.dev/v1alpha1
kind: AgentManifest

identity:
  name: my-agent
  owner: you@company.com

sandbox:
  backend: firecracker        # or: docker
  memory_mb: 512
  network:
    mode: restricted
    allowed:
      - api.anthropic.com

spending:
  max_per_run_usd: "0.50"
  max_per_day_usd: "5.00"

limits:
  max_duration_seconds: 300
```

### Run it

```bash
constle validate agent.yaml          # check the manifest without running anything
constle run agent.yaml               # run the agent in an isolated sandbox
constle ps                           # list agents currently running
constle stop <run-id>                # stop one by run ID
constle identity create              # generate a DID for an agent
constle audit verify <logfile>       # verify an audit log's signature chain
```

---

## The AgentManifest

One declarative file. Constle enforces it identically wherever the runtime is installed:

```yaml
apiVersion: constle.dev/v1alpha1
kind: AgentManifest

identity:
  did: did:key:z6Mk...4doK         # cryptographic identity
  name: invoice-processor
  owner: finance@company.com

sandbox:
  backend: firecracker
  memory_mb: 512
  network:
    mode: restricted
    allowed:
      - api.accounting.internal
      - api.anthropic.com

capabilities:
  mcp_servers:
    - name: accounting-api
    - name: document-reader

spending:
  max_per_run_usd: "0.50"          # enforced by the runtime, not agent code
  max_per_day_usd: "5.00"          # durable per-agent ledger across runs

limits:
  max_duration_seconds: 300

human_gates:
  enabled: true
  triggers:
    - action: external_transfer
    - action: delete_records
  on_timeout: abort               # stop, never proceed
```

Full field reference: [`spec/agent-manifest.md`](spec/agent-manifest.md).

---

## Architecture

Three layers, each shipped and tested today:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 3 - Communication                                    │
│  Signed agent-to-agent messaging · declared peer allowlists │
├─────────────────────────────────────────────────────────────┤
│  Layer 2 - Identity & Governance                             │
│  W3C DID (Ed25519) · human gates · spending limits          │
├─────────────────────────────────────────────────────────────┤
│  Layer 1 - Secure Runtime & Sandbox                          │
│  Firecracker microVM or Docker · network isolation · audit   │
└─────────────────────────────────────────────────────────────┘
```

### How network isolation actually works

The agent process has no default gateway. Every outbound connection passes through a proxy that checks it against the manifest's `network.allowed` list - this holds regardless of which sandbox backend is running:

```
[Agent Process]
      │  no default gateway - there is nowhere else to send a packet
      ▼
[Allowlisting Proxy]  →  declared hosts only
      ✗  →  everything else, silently dropped
```

If a document the agent reads contains a hidden instruction to exfiltrate data somewhere undeclared, that instruction has no path to succeed. The block happens at the network layer, below the model, whether or not the agent "knows" it's compromised.

---

## Try the demo agent

`examples/basic-agent/` is a working agent in Python that calls Claude Haiku via the Anthropic API, run entirely inside a Constle sandbox:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
constle run examples/basic-agent/agent.yaml --env AGENT_TASK="What is 2+2?"
```

---

## CLI reference

| Command | Description |
|---|---|
| `constle run <manifest>` | Run an agent in an isolated sandbox |
| `constle validate <manifest>` | Validate an AgentManifest without running |
| `constle ps` | List Constle-managed agents currently running |
| `constle stop <run-id>` | Stop a running agent by its run ID |
| `constle init` | Scaffold a starter AgentManifest in the current directory |
| `constle identity create` | Generate a new agent DID (Ed25519 key pair) |
| `constle identity show` | Display an agent's DID |
| `constle audit verify <logfile>` | Verify the signature chain of an audit log |

---

## What Constle is not

**Not an agent framework.** Constle doesn't define how an agent reasons or uses tools. LangGraph, CrewAI, or anything else run inside it unchanged - Constle governs the environment, not the logic.

**Not a cloud provider.** It installs on your infrastructure - any cloud or on-premise. Software, not servers.

**Not a monitoring overlay.** Isolation stops exfiltration even if the model itself is fully compromised, because enforcement sits below the agent, not inside it. There's nothing for a compromised agent to disable.

**Not a closed platform.** Apache 2.0. The AgentManifest format is an open, independently auditable standard.

---

## Roadmap

Constle ships in milestones, not on a calendar. See [ROADMAP.md](ROADMAP.md).

---

## Repository structure

```
constle/
├── cmd/constle/          # CLI entry point and subcommands
├── internal/
│   ├── a2a/            # agent-to-agent messaging, gating, and audit
│   ├── audit/          # JSONL audit logger, signing, and verification
│   ├── identity/       # DID-backed agent identity
│   ├── mcpgate/        # protocol-aware human-gate proxy for MCP tool calls
│   ├── sandbox/        # SandboxBackend interface: Docker + Firecracker
│   └── spending/       # runtime-enforced spending ledger
├── pkg/
│   ├── did/            # W3C did:key generation and verification
│   └── manifest/       # AgentManifest types and YAML parser
├── examples/
│   └── basic-agent/    # working demo agent (Python + Anthropic API)
└── spec/
    └── agent-manifest.md  # AgentManifest specification
```

---

## Contributing

Early, solo-maintained, moving fast. See [CONTRIBUTING.md](CONTRIBUTING.md) - bug reports and a gVisor sandbox backend are the most useful contributions right now.

---

## License

[Apache 2.0](LICENSE)

---

**[github.com/constle/constle](https://github.com/constle/constle)**
