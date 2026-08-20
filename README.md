# Constle

<!--
  The `--8<--` comments through this file are section markers, not clutter. The
  documentation site at constle/constle-docs pulls the marked prose straight out
  of this README with pymdownx.snippets, so this file is its single source and
  the two cannot drift. Editing inside a marked section is fine and is the
  point; deleting or unbalancing a marker breaks that repository's build, not
  this one, so it will not show up in CI here.
-->

<!-- --8<-- [start:pitch] -->
**Constle is a runtime that enforces what an AI agent is allowed to do — network, spend, approvals, identity — from outside the agent, so a compromised agent cannot turn the rules off.**
<!-- --8<-- [end:pitch] -->

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go 1.26+](https://img.shields.io/badge/go-1.26+-00ADD8.svg)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/constle/constle)](https://github.com/constle/constle/releases)
[![Build](https://github.com/constle/constle/actions/workflows/release.yaml/badge.svg)](https://github.com/constle/constle/actions)

Full documentation lives at [constle/constle-docs](https://github.com/constle/constle-docs),
publishing to [docs.constle.dev](https://docs.constle.dev).

Enforcement runs in the host process, not the agent's, and that claim is independently checkable: releases are cosign-signed with keyless signing (see [Verifying a release](#verifying-a-release)), and the audit log is hash-chained so an edited entry fails verification rather than passing silently.

<!-- --8<-- [start:demo] -->
You declare the policy in one YAML file. Constle runs the agent inside a sandbox with no default route, routes every packet through an allowlisting proxy, meters cost at the tool-call boundary, pauses sensitive calls for a human, and writes a signed, hash-chained audit log. None of that lives in the agent's process, so there is nothing in it for a prompt injection to disable.

An agent whose manifest declares `allowed_hosts: [api.groq.com]`, reaching for one declared host and one undeclared one:

```
  ┌─ agent output ──────────────────────────
  │ https://api.groq.com/        CONNECT allowed   TLS tunnel opened, server replied
  │ https://evil.example.com/    CONNECT refused   Tunnel connection failed: 403 Forbidden
  └─────────────────────────────────────────

$ grep network ~/.constle/logs/egress-probe-2026-08-08.jsonl
{"event":"network_allowed","details":{"bytes":5314,"host":"api.groq.com","http_status":200,"method":"CONNECT"}}
{"event":"network_blocked","details":{"bytes":3404,"host":"evil.example.com","http_status":403,"method":"CONNECT"}}
```

The second request never left the sandbox. The agent didn't get a refusal from the model — it got no route at all: the proxy declined to open the tunnel, which is the `403` on that line and the only thing that `403` means here. The `200` in the log is the *tunnel* being established for the declared host, not the answer Groq eventually gave; whatever status the real server returns after that is between the agent and the server, and Constle doesn't read it (see [limitation 3](#known-limitations)).

Both attempts are in the audit log either way — the blocked one is how you find out it happened.
<!-- --8<-- [end:demo] -->

---

## Architecture

<!-- The docs site replaces the box drawing below with a rendered diagram, so it
     pulls the prose either side of it as two separate snippets and skips the
     drawing itself. Keep both markers if you edit this section. -->
<!-- --8<-- [start:architecture-intro] -->
Four layers. Three ship today; the fourth does not exist yet and is marked as such.
<!-- --8<-- [end:architecture-intro] -->

```
┌──────────────────────────────────────────────────────────────────────┐
│  Layer 4 — Commerce                                       PLANNED    │
│  Agents discovering and paying each other for work.                  │
│  No code in this repo. Direction only — see ROADMAP.md.              │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 3 — Communication                                  SHIPPED    │
│  A2A: Ed25519-signed envelopes, host-side sign + verify,             │
│  declared peers only, no discovery mechanism by design.              │
│  internal/a2a/                                                       │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 2 — Identity & Governance                          SHIPPED    │
│  W3C did:key identity · signed + hash-chained audit log ·            │
│  human gates at the MCP proxy · per-run and per-day USD ledger.      │
│  internal/identity/  internal/audit/  internal/mcpgate/              │
│  internal/spending/                                                  │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 1 — Runtime & Sandbox                              SHIPPED    │
│  Firecracker microVM or two-network Docker sandbox, no default       │
│  route, Squid egress allowlist, wall-clock kill switch.              │
│  internal/sandbox/                                                   │
└──────────────────────────────────────────────────────────────────────┘
```

<!-- --8<-- [start:architecture-detail] -->
The load-bearing property is the direction of control: every layer runs in the **host** `constle` process, and the agent runs in the sandbox. The agent's private key, the real MCP server URLs, and the real A2A peer endpoints never enter the sandbox at all. The agent talks to per-run gate addresses and nothing else.
<!-- --8<-- [end:architecture-detail] -->

---

## 60-second quickstart

<!-- --8<-- [start:quickstart] -->
Verified end to end on Linux + Docker against `constle v0.4.0`. Copy-paste as-is.

**1. Build the CLI** (Go 1.26+):

```bash
git clone https://github.com/constle/constle
cd constle
go build -o constle ./cmd/constle
```

Pre-built binaries for Linux, macOS, and Windows are on the [releases page](https://github.com/constle/constle/releases); see [Verifying a release](#verifying-a-release) before you trust one.

**2. Check the example manifest without running anything:**

```bash
./constle validate examples/basic-agent/agent.yaml
```

```
✓ examples/basic-agent/agent.yaml is valid

  name:        basic-agent
  version:     0.1.0
  isolation:   network (inferred from capabilities)
  image:       basic-agent:latest
  memory:      512MB
  allowed:     api.groq.com

⚠️  warning: spending limits are declared but NOT enforced:
   no mcp.servers entry declares a pricing block, so there is nothing to meter.
```

That warning is the design working. `examples/basic-agent/agent.yaml` declares `max_per_run_usd: "0.10"` but has no priced MCP server, so there is nothing to meter it against — and Constle says so out loud rather than letting a declared cap look real. See [Known limitations](#known-limitations).

**3. Build the example agent image and run it:**

```bash
docker build -t basic-agent:latest examples/basic-agent
export GROQ_API_KEY=gsk_...            # free key: https://console.groq.com
export AGENT_TASK="What is 2+2?"
./constle run examples/basic-agent/agent.yaml
```

```
constle v0.4.0

  → parsing examples/basic-agent/agent.yaml
  ✓ Agentfile valid
     agent:     basic-agent v0.1.0
     isolation: network
     memory:    512MB
     network:   restricted → api.groq.com
     spending:  run≤$0.10 (NOT ENFORCED — no priced MCP servers)

  → detecting backend
  ✓ backend: docker

  → starting sandbox...
  ✓ sandbox started (run_id: 76935e132f9be8e9)

  ┌─ agent output ──────────────────────────
  │ 2 + 2 = 4
  └─────────────────────────────────────────

✓ run finished    exit=0    duration=2.7s
  audit log: ~/.constle/logs/basic-agent-2026-08-08.jsonl
```

> `constle run` takes no `--env` flag. Exactly three host variables are forwarded into the sandbox — `GROQ_API_KEY`, `ANTHROPIC_API_KEY`, and `AGENT_TASK` (`internal/sandbox/docker.go`, `forwardedHostEnv`). Export them in your shell; they are never written into the image or the manifest.

**4. Sign the audit trail** (optional, ~20 seconds more):

```bash
./constle identity create my-agent --owner=you@example.com
```

Paste the printed `did:key:...` into the manifest under `identity.did`, run again, then:

```bash
./constle audit verify ~/.constle/logs/my-agent-$(date -u +%F).jsonl
```

```
✓ audit log verified: ~/.constle/logs/my-agent-2026-08-08.jsonl

  entries:   2 (all signatures valid, hash chain intact)
  signed by: did:key:z6MkgroKowQYDZjDmqbn82mJv4YFPKowS2xDhxGYrp4u3P1o
```

Edit a single byte of that file and re-run it:

```
error: TAMPERING DETECTED in ~/.constle/logs/my-agent-2026-08-08.jsonl
  line 1: invalid_signature — signature does not verify against did:key:z6Mkg… — the entry was edited after signing
```

With `identity.did` set, `constle run` also **fails closed**: if the manifest names a DID with no matching private key on this machine, the run refuses to start rather than proceeding under an identity it cannot actually prove.
<!-- --8<-- [end:quickstart] -->

---

## Known limitations

<!-- The docs site puts a summary diagram of all five between these two snippets,
     so the intro and the detail are pulled separately. -->
<!-- --8<-- [start:limitations-intro] -->
These are known, deliberate, and load-bearing to read before you trust anything above. Each one is a case where a manifest field looks stronger than the runtime currently is, and each is stated in the code at the point where it matters.
<!-- --8<-- [end:limitations-intro] -->

<!-- --8<-- [start:limitations-detail] -->
### 1. Human gates match MCP tool names by exact string, and nothing else

`human_gates.require_approval_for` gates a call when an entry is a **byte-exact, case-sensitive match** for the `params.name` of a `tools/call` request on a server declared under `mcp.servers`. The tool name is the only protocol-level identifier the gate proxy sees, and exact match is the only mapping that is deterministic and auditable — there is no semantic matching, no prefix matching, no wildcards.

**What this means for you:** an entry like `external_transfer` gates *nothing* unless an MCP server actually exposes a tool named exactly `external_transfer`. Constle warns about every unmatched entry at both `validate` and `run` time, so an unenforceable gate is loud rather than silent — but it is still unenforceable. Human gates also do not apply to plain HTTPS traffic through `allowed_hosts`; the gate proxy only sees MCP.

*Source: `pkg/manifest/manifest.go` (`HumanGates.RequireApprovalFor`, "MAPPING CONTRACT"), `cmd/constle/gates.go`.*

### 2. `max_per_month_usd` is parsed but not enforced

The field is accepted by the parser and validated as a decimal amount. Nothing enforces it. Declaring it produces an explicit warning and no monthly ledger exists. `max_per_run_usd` and `max_per_day_usd` **are** enforced (the daily one durably, across runs, keyed by DID).

*Source: `pkg/manifest/manifest.go` (`Spending.MaxPerMonthUSD`).*

### 3. Traffic through `allowed_hosts` is not metered for spending

Cost is metered **only** at the MCP gate proxy, against the `pricing` block a server declares. Ordinary HTTPS to a host in `network.allowed_hosts` — including every direct call to an LLM API — is allowlisted, logged, and **not** counted toward any spending cap.

This is a deliberate privacy trade-off, not an oversight: metering that traffic would require Constle to TLS-intercept the agent's connections and read their contents, and Constle refuses to do that. The consequence is real and you should size it: **an agent that spends money over `allowed_hosts` rather than through a priced MCP server has no spending enforcement at all.** That is exactly the case the quickstart's example hits, and why it prints `NOT ENFORCED`.

*Source: `pkg/manifest/manifest.go` (`Spending`, "Enforcement scope"), `internal/mcpgate/metering.go`.*

### 4. The A2A replay guard is in-memory and per-run

The A2A listener rejects duplicate `msg_id`s and envelopes whose timestamp drifts more than ±5 minutes from the local clock. The set of seen message IDs lives in process memory and does not survive a `constle` restart.

**What this means:** an envelope captured during one run can be replayed against a *later* run, provided the replay lands inside the 5-minute timestamp window. Durable, cross-run replay state is out of scope for this version. The mitigation available today is the timestamp window itself — keep runs of the same agent separated by more than 5 minutes if replay across runs is in your threat model.

*Source: `internal/a2a/envelope.go` (`replayGuard`).*

### 5. `sandbox.network.egress` is declared but has no consumer

The field parses, validates, and defaults to `restricted` — and then nothing reads it. All egress enforcement is derived **solely** from `network.allowed_hosts`, which becomes the Squid `dstdomain` allowlist. An empty list denies everything.

So `egress: open` and `egress: none` both parse cleanly, change nothing about what the agent can reach, and still render as `restricted` in the run summary. This is the one gap in this list that is a declared policy which *looks* real and is not, which is precisely what the warnings in items 1 and 2 exist to prevent elsewhere. Fixing it means deciding what `egress: open` should *do*, not just what it should print — until that decision is made, the display label is deliberately not derived from the field, because deriving it would make the output honest about a value the runtime still ignores.

**Until then: treat `allowed_hosts` as the entire network policy. It is.** An empty or absent `allowed_hosts` is your "deny all"; `egress` is documentation.

*Source: `cmd/constle/main.go` (`renderRunSummary`, "KNOWN GAP"), recorded in [#16](https://github.com/constle/constle/issues/16).*
<!-- --8<-- [end:limitations-detail] -->

---

## What Constle enforces

<!-- --8<-- [start:enforces] -->
| Capability | Mechanism | Status |
|---|---|---|
| **Sandboxed execution** | Firecracker microVM (hardware isolation) or a two-network Docker sandbox with no default gateway. Auto-detected, or forced with `--backend=docker\|firecracker`. `isolation: kernel` selects Firecracker and warns loudly if it has to fall back to Docker. | Shipped |
| **Network egress** | All egress traverses a Squid proxy allowlisting `network.allowed_hosts`. Matching is name-based (`dstdomain`), and a separate rule denies destinations given as raw IPs — including the real IP of an allowed host — so resolving a name yourself and connecting to the address is not a way around the allowlist. Every allow and every block is an audit event. | Shipped |
| **Max duration** | The agent is killed when `limits.max_duration_seconds` elapses; the kill is recorded as `terminated_by_limit`. | Shipped |
| **Audit log** | JSONL per agent per UTC day. With `identity.did` set, every entry is Ed25519-signed and hash-chained; `constle audit verify` detects tampering and reports the offending line. | Shipped |
| **Spending limits** | Hard `max_per_run_usd` and `max_per_day_usd`. Metered at the MCP gate against each server's declared `pricing`. The daily ledger is durable across runs, keyed by DID so a rename can't reset it. A priced server whose response omits a declared usage value kills the run — a server that could omit its usage field could zero its own bill. **Scope caveats: limitations 2 and 3.** | Shipped |
| **Human gates** | Declared MCP servers are reachable only through a protocol-aware gate proxy. A matching `tools/call` pauses for a terminal approval; `on_timeout` defaults to `abort`. Non-interactive stdin (CI, piped input, backgrounded runs) is detected up front and announced, rather than blocking on a read that never resolves — the call then waits out its deadline and `on_timeout` decides. **Matching caveat: limitation 1.** | Shipped |
| **Cryptographic identity** | W3C `did:key` (Ed25519). The private key stays at `~/.constle/identities/<name>/` (mode 0600) and never enters the sandbox. `constle run` fails closed on a declared DID with no local key. | Shipped |
| **Agent-to-agent messaging** | Signed envelopes to explicitly declared peers only. The host signs and verifies; the sandbox does no cryptography and never sees a peer's real endpoint. No discovery mechanism exists, by design. **Replay caveat: limitation 4.** | Shipped |
| **Agent commerce** | — | Not built |

Constle is **not a framework.** It doesn't decide how an agent reasons or plans. LangGraph, CrewAI, or hand-rolled code run inside it unchanged.
<!-- --8<-- [end:enforces] -->

---

## The Agentfile

<!-- --8<-- [start:agentfile] -->
One declarative file, enforced identically wherever the runtime is installed. This example uses every field the runtime actually consumes:

```yaml
apiVersion: constle.dev/v1alpha1
kind: AgentManifest

identity:
  name: invoice-processor
  version: "1.0.0"
  owner: finance@company.com
  did: did:key:z6Mk...4doK        # from `constle identity create`; only the public DID lives here

sandbox:
  image: invoice-processor:latest
  isolation: kernel               # or omit — inferred from capabilities
  memory_mb: 512
  network:
    egress: restricted            # declared only — see limitation 5
    allowed_hosts:                # this list IS the network policy
      - api.groq.com

capabilities:                     # a flat list of strings, not a map
  - external_api
  - external_transfer

mcp:
  servers:
    - id: accounting
      url: https://mcp.accounting.internal   # host-side only; never enters the sandbox
      tools: [list_invoices, pay_invoice]    # optional allowlist
      pricing:                               # required for spending to be enforced
        meters:
          - usage_path: result.usage.input_tokens
            usd_per_unit: "0.000003"
          - usage_path: result.usage.output_tokens
            usd_per_unit: "0.000015"

spending:
  max_per_run_usd: "0.50"
  max_per_day_usd: "5.00"         # durable across runs; requires identity.did
  alerts:
    warn_at_pct_of_daily: 80

limits:
  max_duration_seconds: 300

human_gates:
  enabled: true
  require_approval_for:
    - pay_invoice                 # must exactly match an MCP tool name — limitation 1
  approval_timeout_seconds: 300
  on_timeout: abort               # default; stop, never proceed

a2a:
  listen: ":9443"
  peers:
    - name: auditor
      did: did:key:z6Mk...9xQz
      endpoint: https://auditor.internal:9443

compliance:
  audit_log_level: standard       # none | minimal | standard | verbose
```

`constle init` scaffolds a starter file with these defaults. Full field reference: [`spec/agent-manifest.md`](spec/agent-manifest.md), plus [`spec/a2a.md`](spec/a2a.md) and [`spec/identity.md`](spec/identity.md).

[`spec/agent-manifest.yaml`](spec/agent-manifest.yaml) is an annotated reference file covering every supported field. It is executable, not aspirational — `constle validate spec/agent-manifest.yaml` passes, and fields that are parsed but not yet enforced are labelled as such inline.
<!-- --8<-- [end:agentfile] -->

---

## How network isolation actually works

<!-- The docs site draws this next hop as a diagram, so the snippet it pulls
     starts after the box drawing rather than at the top of the section. -->
```
[Agent process]
      │  no default route, IPv4 or IPv6 — there is nowhere else to send a packet
      ▼
[Squid allowlist proxy]  ──▶  hosts in network.allowed_hosts        → network_allowed
                         ──✗  everything else, including raw IPs    → network_blocked (403)
```

<!-- --8<-- [start:network] -->
The agent process has no route to the internet. The only reachable next hop is the proxy, which checks each `CONNECT` against `allowed_hosts`. Both backends render this policy from the same function (`buildSquidConfig`, `internal/sandbox/docker.go`), so Docker and Firecracker enforce the same ruleset.

Resolving a hostname inside the sandbox and connecting to the resulting address does not get around it — the raw IP of an allowed host is denied along with every other IP literal, because the allowlist is a `dstdomain` ACL that an address can never match:

```
declared hostname              https://api.groq.com/      CONNECT allowed
raw IP OF THE DECLARED HOST    https://172.64.149.20/     Tunnel connection failed: 403 Forbidden
raw IP, undeclared             https://1.1.1.1/           Tunnel connection failed: 403 Forbidden
undeclared hostname            https://evil.example.com/  Tunnel connection failed: 403 Forbidden
```

### Ignoring the proxy isn't an option either

Everything above assumes the agent goes *through* the proxy. It can't do otherwise: the sandbox has no route that reaches anything else. On Docker the agent's network is created `--internal`, its routing table holds a single on-link entry and no default route at all, and the only address family present is IPv4. Attempting to dial out directly, with the proxy environment cleared:

```
IPv6  2606:4700:4700::1111   OSError: [Errno 101] Network is unreachable
IPv4  1.1.1.1                OSError: [Errno 101] Network is unreachable
```

DNS doesn't resolve in there either — the sandbox cannot look up an address, let alone route to one.

IPv6 in particular is closed on both backends, and closed *deterministically rather than environment-dependently*: the internal network is created with an explicit `--ipv6=false` instead of inheriting whatever the operator's Docker daemon defaults to, so this guarantee is a property of the code and not of the host it runs on. The Firecracker guest gets only a kernel-generated link-local `fe80::` address, never a global one or a `::/0` route, and its per-run nftables table drops the tap interface in the dual-family `inet` table — so the same rule covers both families.

One caveat, stated because it's the kind of thing that rots quietly: the proxy's raw-IP ACL (`ip_only`) is IPv4-only, with no `::/0` counterpart. Nothing rides on it today — an IPv6 literal is refused by the config's trailing `deny all`, and nothing can reach the proxy over IPv6 anyway — but it would become a real gap if a future change gave a sandbox an IPv6 route without adding the matching rule. It's flagged in the code at `buildSquidConfig`.

### What this does not cover

The proxy trusts DNS. If a declared hostname resolves to an address an attacker controls, the allowlist will let it through — name-based allowlisting is only as good as the name resolution behind it.

If a document the agent reads contains a hidden instruction to exfiltrate data to an undeclared host, that instruction has no path to succeed. The block happens at the network layer, below the model, whether or not the agent "knows" it is compromised — and the attempt lands in the audit log as a `network_blocked` event, which is how you find out it happened.
<!-- --8<-- [end:network] -->

---

## CLI reference

<!-- --8<-- [start:cli] -->
| Command | Description |
|---|---|
| `constle run [--backend=docker\|firecracker] <agentfile>` | Run an agent in an isolated sandbox |
| `constle validate <agentfile>` | Validate an Agentfile without running it |
| `constle init` | Scaffold a starter Agentfile in the current directory |
| `constle ps` | List running and recent Constle-managed agents |
| `constle stop <run-id>` | Stop a running agent by run ID |
| `constle identity create <name> [--owner=<email>]` | Generate an agent DID (Ed25519 key pair) |
| `constle identity show <name>` | Show an agent's DID and key location |
| `constle audit verify [--did=<did:key:…>] <logfile>` | Verify an audit log's signatures and hash chain |
| `constle version` | Print the version |
<!-- --8<-- [end:cli] -->

---

## Verifying a release

<!-- --8<-- [start:verify] -->
Every release ships a `checksums.txt` covering all archives, signed with [cosign](https://docs.sigstore.dev/) keyless signing from the release workflow. Download `checksums.txt`, `checksums.txt.sig`, and `checksums.txt.pem` next to your archive, then:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/constle/constle/\.github/workflows/release\.yaml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt

sha256sum --check --ignore-missing checksums.txt
```

The two `--certificate-*` flags are **not optional.** Keyless signing has no fixed public key: anyone can obtain a valid Fulcio certificate and sign anything. Without pinning the identity, cosign will report `Verified OK` for a file signed by a complete stranger — all that proves is that *somebody* signed it. Pinning to `constle/constle`'s `release.yaml` on a `v*` tag, issued by GitHub's OIDC issuer, is what turns the signature into "this came from the Constle release workflow."

Each archive also carries a SLSA build-provenance attestation:

```bash
gh attestation verify constle_<version>_linux_amd64.tar.gz --repo constle/constle
```
<!-- --8<-- [end:verify] -->

---

## What Constle is not

<!-- --8<-- [start:isnot] -->
**Not an agent framework.** It governs the environment, not the logic.

**Not a cloud provider.** It installs on your infrastructure, any cloud or on-premise. Software, not servers.

**Not a monitoring overlay.** Isolation stops exfiltration even if the model is fully compromised, because enforcement sits below the agent rather than inside it. There is nothing for a compromised agent to disable.

**Not finished.** See [Known limitations](#known-limitations) — they are listed there rather than discovered later.

**Not a closed platform.** Apache 2.0, and the Agentfile format is an open, independently auditable standard.
<!-- --8<-- [end:isnot] -->

---

## Beyond this file

Full docs, including everything pulled from this README, are at [docs.constle.dev](https://docs.constle.dev). Constle ships in milestones, not on a calendar — see [ROADMAP.md](ROADMAP.md). It's early and solo-maintained; see [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR — the most useful contributions right now are bug reports, a gVisor sandbox backend, and anything that closes a row in [Known limitations](#known-limitations). Security issues: see [SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE)
