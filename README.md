<!--
  The `--8<--` comments through this file are section markers, not clutter. The
  documentation site at constle/constle-docs pulls the marked prose straight out
  of this README with pymdownx.snippets, so this file is its single source and
  the two cannot drift. Editing inside a marked section is fine and is the
  point; deleting or unbalancing a marker breaks that repository's build, not
  this one, so it will not show up in CI here.
-->

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/constle-lockup-loop-dark.gif">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/brand/constle-lockup-loop-light.gif">
    <img src="docs/assets/brand/constle-lockup-loop-light.gif" alt="Constle" width="600">
  </picture>
</p>

<p align="center">
<!-- --8<-- [start:pitch] -->
<strong>Constle is a runtime that enforces what an AI agent is allowed to do — network, spend, approvals, identity — from outside the agent, so a compromised agent cannot turn the rules off.</strong>
<!-- --8<-- [end:pitch] -->
</p>

<p align="center">

[![License](https://img.shields.io/badge/license-Apache%202.0-0D1117?style=for-the-badge)](https://github.com/constle/constle/blob/main/LICENSE) [![Go](https://img.shields.io/badge/go-1.26+-6366F1?style=for-the-badge&logo=go&logoColor=white)](https://golang.org) [![Release](https://img.shields.io/github/v/release/constle/constle?style=for-the-badge&color=22C55E&label=release)](https://github.com/constle/constle/releases) [![Build](https://github.com/constle/constle/actions/workflows/release.yaml/badge.svg)](https://github.com/constle/constle/actions) [![Docs](https://img.shields.io/badge/docs-docs.constle.dev-F59E0B?style=for-the-badge)](https://docs.constle.dev)

</p>

> [!IMPORTANT]
> Constle is early and solo-maintained (v0.5.0, pre-1.0) — interfaces may still change before a 1.0 release. Read [Known limitations](#known-limitations) before you rely on any of this.

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

The second request never left the sandbox — the proxy declined to open the tunnel. Both attempts land in the audit log either way; the blocked one is how you find out it happened. Raw-IP bypass attempts, IPv6, and the DNS trust boundary: [docs.constle.dev/network-isolation](https://docs.constle.dev/network-isolation/).
<!-- --8<-- [end:demo] -->

---

## Architecture

<!-- The docs site replaces the box drawing below with a rendered diagram, so it
     pulls the prose either side of it as two separate snippets and skips the
     drawing itself. Keep both markers if you edit this section. -->
<!-- --8<-- [start:architecture-intro] -->
Four layers. Three ship today; the fourth doesn't exist yet.
<!-- --8<-- [end:architecture-intro] -->

```
┌──────────────────────────────────────────────────────────────────────┐
│  Layer 4 — Commerce                                       PLANNED    │
│  Agents discovering and paying each other for work. See ROADMAP.md.  │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 3 — Communication                                  SHIPPED    │
│  A2A: Ed25519-signed envelopes, host-side sign + verify,             │
│  declared peers only.                              internal/a2a/     │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 2 — Identity & Governance                          SHIPPED    │
│  did:key identity · signed + hash-chained audit log · human gates ·  │
│  per-run/per-day USD ledger.        internal/identity, audit,        │
│                                     mcpgate, spending                │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 1 — Runtime & Sandbox                              SHIPPED    │
│  Firecracker microVM or two-network Docker sandbox, no default       │
│  route, Squid egress allowlist.                    internal/sandbox/ │
└──────────────────────────────────────────────────────────────────────┘
```

<!-- --8<-- [start:architecture-detail] -->
Every layer runs in the **host** `constle` process — the agent's private key, the real MCP server URLs, and the real A2A peer endpoints never enter the sandbox. Full capability-by-capability breakdown (mechanism + status for all nine): [docs.constle.dev](https://docs.constle.dev/#what-constle-enforces).

Constle is **not a framework.** It doesn't decide how an agent reasons or plans — LangGraph, CrewAI, or hand-rolled code run inside it unchanged.
<!-- --8<-- [end:architecture-detail] -->

---

## What Constle enforces

<details markdown="1">
<summary><strong>All nine capabilities — mechanism and status</strong></summary>

<!-- --8<-- [start:enforces] -->
| Capability | Mechanism | Status |
|---|---|---|
| **Sandboxed execution** | Firecracker microVM (hardware isolation) or a two-network Docker sandbox with no default gateway. Auto-detected, or forced with `--backend=docker\|firecracker`. A declared `isolation:` level is a minimum contract on two axes. Against `capabilities`: it may be stronger than they require but never weaker, or the Agentfile is rejected at validate time naming the capability that forces the floor. Against the host: `isolation: kernel` selects Firecracker and the run **fails closed** if Firecracker is unavailable, unless an operator explicitly accepts a weaker boundary with `--accept-isolation=<level>` — which covers that axis only and cannot waive the capability-floor rejection, though it can still put one run on a weaker boundary, named by the operator and recorded. | Shipped |
| **Network egress** | All egress traverses a Squid proxy allowlisting `network.allowed_hosts`. Matching is name-based (`dstdomain`) with reverse lookups off, so a destination given as a raw IP is denied — including the real IP of an allowed host, and including an address whose PTR record names one — and resolving a name yourself is not a way around the allowlist. An allowed name does not decide where it points or what rides over it: destinations in loopback, link-local, metadata and private ranges are refused on the resolved address, and `CONNECT` is confined to 443. Every allow and every block is an audit event. | Shipped |
| **Max duration** | The agent is killed when `limits.max_duration_seconds` elapses; the kill is recorded as `terminated_by_limit`. | Shipped |
| **Audit log** | JSONL per agent per UTC day. With `identity.did` set, every entry is Ed25519-signed and hash-chained; `constle audit verify` detects tampering and reports the offending line. | Shipped |
| **Spending limits** | Hard `max_per_run_usd` and `max_per_day_usd`. Metered at the MCP gate against each server's declared `pricing`. The daily ledger is durable across runs, keyed by DID so a rename can't reset it. A priced server whose response omits a declared usage value kills the run — a server that could omit its usage field could zero its own bill. **Scope caveats: limitations 2 and 3.** | Shipped |
| **Human gates** | Declared MCP servers are reachable only through a protocol-aware gate proxy. A matching `tools/call` pauses for approval — at the terminal, and, when `approver_pubkey` is set **and** a `notify` webhook URL resolves, also at a signed decision channel that runs concurrently with it, first decision winning. A decision that arrives is verified and can only deny: a bad signature, a mismatched digest or request id, or any value but `approved` refuses the call, and no setting relaxes that. A gate that reaches its deadline with **no** decision from either channel is resolved by `on_timeout` instead, which defaults to `abort` (refuse the call, stop the run) and may be set to `proceed` (forward it unapproved) — so a broken or absent decision channel fails toward whichever of those the operator chose. Non-interactive stdin (CI, piped input, backgrounded runs) is detected up front and announced, rather than blocking on a read that never resolves — the call then waits out its deadline and `on_timeout` decides. The gate accepts only the three methods the MCP transport defines (`POST`, `GET`, `DELETE`) and only accepts a JSON-RPC body on a `POST`, so a tool call cannot be re-sent on a method that skips inspection. A body it cannot read exactly one way — two members of an object that are equal, or that differ only in case, at any depth — is refused rather than resolved, so the call the gate inspects is the call the upstream's own parser runs. A sub-path after the server id may only descend below the declared endpoint: any segment a second reading of the same bytes would turn into structure — a dot segment however encoded, a doubled slash, a path parameter, a percent sign that survives one decode — is refused rather than normalised, and so is a declared endpoint that is itself ambiguous. A protocol upgrade is refused in both directions, so no request can turn the gate into a tunnel it cannot inspect. **Matching caveat: limitation 1.** | Shipped |
| **Cryptographic identity** | W3C `did:key` (Ed25519). The private key stays at `~/.constle/identities/<name>/` (mode 0600) and never enters the sandbox. `constle run` fails closed on a declared DID with no local key. | Shipped |
| **Agent-to-agent messaging** | Signed envelopes to explicitly declared peers only. The host signs and verifies; the sandbox does no cryptography and never sees a peer's real endpoint. No discovery mechanism exists, by design. **Replay caveat: limitation 4.** | Shipped |
| **Agent commerce** | - | Not built |
<!-- --8<-- [end:enforces] -->

</details>

---

## How network isolation actually works

<details markdown="1">
<summary><strong>No default route, a <code>dstdomain</code> allowlist, and why the proxy cannot be skipped</strong></summary>

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

Resolving a hostname inside the sandbox and connecting to the resulting address does not get around it — the raw IP of an allowed host is denied along with every other IP literal, because the allowlist is a `dstdomain` ACL built with reverse lookups disabled: an address is admitted only if that same address was itself listed, never by being resolved back to a name. Without that, an address whose PTR record named an allowed host was admitted too — and a PTR record is written by whoever owns the address, not by whoever wrote the allowlist.

```
declared hostname              https://api.groq.com/      CONNECT allowed
raw IP OF THE DECLARED HOST    https://172.64.149.20/     Tunnel connection failed: 403 Forbidden
raw IP, undeclared             https://1.1.1.1/           Tunnel connection failed: 403 Forbidden
undeclared hostname            https://evil.example.com/  Tunnel connection failed: 403 Forbidden
```

An allowed name is not a blank cheque on where it points, or on what travels over it. A name resolving into the sandbox host, the host's own network, or a cloud metadata address is refused at the proxy whatever DNS answered — that check is made on the resolved address, which is the only place it can be made. And a tunnel to an allowed host is a tunnel to its HTTPS port: a request may name port 80 or 443, and a `CONNECT` tunnel may name 443 alone, so an allowed hostname cannot become a raw TCP path to an SSH or database port, whose contents the proxy could not see in any case.

```
allowed host, HTTPS       CONNECT api.groq.com:443   TCP_TUNNEL/200   → network_allowed
allowed host, port 22     CONNECT api.groq.com:22    TCP_DENIED/403   → network_blocked
allowed name → 127.0.0.1  CONNECT localtest.me:443   TCP_DENIED/403   → network_blocked
address whose PTR is one  CONNECT 1.1.1.1:443        TCP_DENIED/403   → network_blocked
```

### Ignoring the proxy isn't an option either

Everything above assumes the agent goes *through* the proxy. It can't do otherwise: the sandbox has no route that reaches anything else. On Docker the agent's network is created `--internal`, its routing table holds a single on-link entry and no default route at all, and the only address family present is IPv4. Attempting to dial out directly, with the proxy environment cleared:

```
IPv6  2606:4700:4700::1111   OSError: [Errno 101] Network is unreachable
IPv4  1.1.1.1                OSError: [Errno 101] Network is unreachable
```

DNS doesn't resolve in there either — the sandbox cannot look up an address, let alone route to one.

IPv6 in particular is closed on both backends, and closed *deterministically rather than environment-dependently*: the internal network is created with an explicit `--ipv6=false` instead of inheriting whatever the operator's Docker daemon defaults to, so this guarantee is a property of the code and not of the host it runs on. The Firecracker guest gets only a kernel-generated link-local `fe80::` address, never a global one or a `::/0` route, and its per-run nftables table drops the tap interface in the dual-family `inet` table — so the same rule covers both families.

The proxy's own rules cover both families rather than relying on the sandbox only ever speaking one: the raw-IP ACL is spelled `dst all`, and the internal-destination rule lists the IPv6 loopback, link-local and unique-local ranges beside the IPv4 ones. It used to be an IPv4-only `0.0.0.0/0`, which Squid quietly rewrote to `all` while announcing the substitution as a security notice — an ACL that means something other than what it says is the kind of thing that rots quietly, so the generated config is now parsed by a real Squid in the test suite and any complaint at all fails the build.

### What this does not cover

The proxy trusts DNS for public addresses. If a declared hostname resolves to a public address an attacker controls, the allowlist will let it through — name-based allowlisting is only as good as the name resolution behind it. What DNS cannot do is aim a declared name back inside: loopback, link-local, metadata and private destinations are refused on the resolved address, whatever the record says.

If a document the agent reads contains a hidden instruction to exfiltrate data to an undeclared host, that instruction has no path to succeed. The block happens at the network layer, below the model, whether or not the agent "knows" it is compromised — and the attempt lands in the audit log as a `network_blocked` event, which is how you find out it happened.
<!-- --8<-- [end:network] -->

</details>

---

## 60-second quickstart

<!-- --8<-- [start:quickstart] -->
Verified end to end on Linux + Docker against `constle v0.5.0`. Copy-paste as-is.

**1. Build the CLI** (Go 1.26+):

```
git clone https://github.com/constle/constle
cd constle
go build -o constle ./cmd/constle
```

Or install a pre-built binary for Linux, macOS, or Windows:

```
curl -fsSL https://constle.dev/install | sh        # Linux, macOS
iwr -useb https://constle.dev/install.ps1 | iex    # Windows PowerShell
```

The installer fetches `checksums.txt` for the release it is installing and refuses to unpack an archive whose SHA-256 does not match. When `cosign` is on your PATH it checks the release workflow's signature over `checksums.txt` first, pinned to the identity in [Verifying a release](#verifying-a-release), and aborts if that fails; without `cosign` it says so on the terminal and enforces the checksum alone. Downloading an archive by hand from the [releases page](https://github.com/constle/constle/releases) skips all of this — see [Verifying a release](#verifying-a-release) before you trust one.

**2. Check the example manifest without running anything:**

```
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

> [!WARNING]
> That warning is the design working, not a bug — a declared cap with nothing metering it gets called out loudly instead of quietly looking real. See [Known limitations](#known-limitations).

**3. Build the example agent image and run it:**

```
docker build -t basic-agent:latest examples/basic-agent
export GROQ_API_KEY=gsk_...            # free key: https://console.groq.com
export AGENT_TASK="What is 2+2?"
./constle run examples/basic-agent/agent.yaml
```

```
constle v0.5.0

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

> [!NOTE]
> `constle run` takes no `--env` flag. Exactly three host variables are forwarded into the sandbox — `GROQ_API_KEY`, `ANTHROPIC_API_KEY`, and `AGENT_TASK` — and they're never written into the image or the manifest.

**4. Sign the audit trail** (optional, ~20 seconds more): `constle identity create`, paste the DID into the manifest, run again, then `constle audit verify` catches a single edited byte.

<details markdown="1">
<summary><strong>The four commands, and what tampering looks like when it is caught</strong></summary>

```
./constle identity create my-agent --owner=you@example.com
```

Paste the printed `did:key:...` into the manifest under `identity.did`, run again, then:

```
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

</details>
<!-- --8<-- [end:quickstart] -->

---

## The Agentfile

<!-- --8<-- [start:agentfile] -->
One declarative file, enforced identically wherever the runtime is installed. Every field the runtime actually consumes:

> [!TIP]
> `constle init` scaffolds a starter Agentfile with sane defaults — start there instead of copying this example by hand.

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
    allowed_hosts:                # this list IS the network policy
      - api.groq.com

capabilities:
  - external_api
  - external_transfer

mcp:
  servers:
    - id: accounting
      url: https://mcp.accounting.internal   # host-side only; never enters the sandbox
      tools: [list_invoices, pay_invoice]
      pricing:                               # required for spending to be enforced
        meters:
          - usage_path: result.usage.input_tokens
            usd_per_unit: "0.000003"

spending:
  max_per_run_usd: "0.50"
  max_per_day_usd: "5.00"         # durable across runs; requires identity.did

limits:
  max_duration_seconds: 300

human_gates:
  enabled: true
  require_approval_for:
    - pay_invoice                 # must exactly match an MCP tool name — limitation 1
  on_timeout: abort                # default; stop, never proceed

a2a:
  listen: ":9443"
  peers:
    - name: auditor
      did: did:key:z6Mk...9xQz
      endpoint: https://auditor.internal:9443
```

Full field reference: [docs.constle.dev/reference/agent-manifest](https://docs.constle.dev/reference/agent-manifest/). CLI command reference: [docs.constle.dev/cli](https://docs.constle.dev/cli/).
<!-- --8<-- [end:agentfile] -->

---

## Known limitations

> [!IMPORTANT]
> Read these before you rely on anything above.

<!-- The docs site puts a summary diagram of all five between these two snippets,
     so the intro and the detail are pulled separately. -->
<!-- --8<-- [start:limitations-intro] -->
Five gaps, all documented and deliberate rather than discovered later. Each one is a case where a manifest field looks stronger than the runtime currently is, and each is stated in the code at the point where it matters.
<!-- --8<-- [end:limitations-intro] -->

1. **Human gates match MCP tool names by exact string only** — no wildcards, no semantic matching, and they don't apply to plain HTTPS traffic through `allowed_hosts`.
2. **`max_per_month_usd` is parsed but not enforced** — only `max_per_run_usd` and `max_per_day_usd` are.
3. **Traffic through `allowed_hosts` isn't metered for spending** — only the MCP gate is. An agent that spends money over `allowed_hosts` has no spending enforcement at all.
4. **The A2A replay guard is in-memory and per-run** — it doesn't survive a `constle` restart.
5. **`sandbox.network.egress` is declared but has no consumer** — `allowed_hosts` is the entire network policy; treat an empty list as "deny all."

<details markdown="1">
<summary><strong>Full explanation and source reference for each</strong></summary>

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

### 4. A2A replay state is per machine, not shared between machines

The A2A listener rejects duplicate `msg_id`s and envelopes whose timestamp drifts more than ±5 minutes from the local clock. The set of seen message IDs is durable: every accepted id is persisted under `~/.constle/a2a/replay/<did>/`, so the check spans process restarts and concurrent runs of the same identity — and fails closed (a retryable 503) if that state cannot be read or written. What it does **not** span is machines: the state lives in the invoking user's home and is not replicated anywhere.

**What this means:** if you run the *same* identity as a listener on more than one machine, an envelope captured in flight can be replayed once per machine, provided each replay lands inside the 5-minute timestamp window. One listening machine per identity — the normal deployment — has no such exposure.

*Source: `internal/a2a/envelope.go` (`replayGuard`), `internal/a2a/replay_store.go`.*

### 5. `sandbox.network.egress` is declared but has no consumer

The field parses, validates, and defaults to `restricted` — and then nothing reads it. All egress enforcement is derived **solely** from `network.allowed_hosts`, which becomes the Squid `dstdomain` allowlist. An empty list denies everything.

So `egress: open` and `egress: none` both parse cleanly, change nothing about what the agent can reach, and still render as `restricted` in the run summary. This is the one gap in this list that is a declared policy which *looks* real and is not, which is precisely what the warnings in items 1 and 2 exist to prevent elsewhere. Fixing it means deciding what `egress: open` should *do*, not just what it should print — until that decision is made, the display label is deliberately not derived from the field, because deriving it would make the output honest about a value the runtime still ignores.

**Until then: treat `allowed_hosts` as the entire network policy. It is.** An empty or absent `allowed_hosts` is your "deny all"; `egress` is documentation.

*Source: `cmd/constle/main.go` (`renderRunSummary`, "KNOWN GAP"), recorded in [#16](https://github.com/constle/constle/issues/16).*
<!-- --8<-- [end:limitations-detail] -->

</details>

Also on the docs site: [docs.constle.dev/limitations](https://docs.constle.dev/limitations/).

---

## What Constle is not

<!-- --8<-- [start:isnot] -->
**Not an agent framework.** It governs the environment, not the logic.

**Not a cloud provider.** It installs on your infrastructure, any cloud or on-premise.

**Not a monitoring overlay.** Isolation stops exfiltration even if the model is fully compromised, because enforcement sits below the agent rather than inside it.

**Not finished.** See [Known limitations](#known-limitations) — they're listed here rather than discovered later.

**Not a closed platform.** Apache 2.0, and the Agentfile format is an open, independently auditable standard.
<!-- --8<-- [end:isnot] -->

---

## CLI reference

<details markdown="1">
<summary><strong>Every <code>constle</code> subcommand</strong></summary>

<!-- --8<-- [start:cli] -->
| Command | Description |
|---|---|
| `constle [--no-animation]` | Show the startup screen and command overview |
| `constle run [--backend=docker\|firecracker] [--accept-isolation=<level>] <agentfile>` | Run an agent in an isolated sandbox |
| `constle validate <agentfile>` | Validate an Agentfile without running it |
| `constle init` | Scaffold a starter Agentfile in the current directory |
| `constle ps` | List running and recent Constle-managed agents |
| `constle stop <run-id>` | Stop a running agent by run ID |
| `constle identity create <name> [--owner=<email>]` | Generate an agent DID (Ed25519 key pair) |
| `constle identity show <name>` | Show an agent's DID and key location |
| `constle audit verify [--did=<did:key:…>] <logfile>` | Verify an audit log's signatures and hash chain |
| `constle version` | Print the version |

Running bare `constle` in an interactive terminal plays the startup animation before the command overview. Use `constle --no-animation` to skip it for one invocation, or set `CONSTLE_ANIMATION` to `auto` (the default), `never`, or `always`. The animation is always suppressed for non-interactive output, `NO_COLOR`, `TERM=dumb`, or terminals smaller than 80×24; `always` overrides CI detection only.
<!-- --8<-- [end:cli] -->

</details>

---

## Verifying a release

<!-- --8<-- [start:verify] -->
Every release ships a `checksums.txt`, signed with [cosign](https://docs.sigstore.dev/) keyless signing pinned to this repo's release workflow:

```
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/constle/constle/\.github/workflows/release\.yaml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

> [!CAUTION]
> The two `--certificate-*` flags are **not optional.** Keyless signing has no fixed public key — without pinning the identity, cosign will report `Verified OK` for a file signed by anyone. Pinning to `constle/constle`'s release workflow is what turns the signature into proof it came from here.

Provenance attestation: `gh attestation verify constle_<version>_linux_amd64.tar.gz --repo constle/constle`.

The one-line installer at `constle.dev/install` does the checksum half of this on every run, and the `cosign` half too when `cosign` is on your PATH; it says so on the terminal when it cannot. `CONSTLE_REQUIRE_SIGNATURE=1` makes the signature mandatory — no release publishes one yet, so today that setting refuses every install.
<!-- --8<-- [end:verify] -->

---

## Roadmap & contributing

Constle ships in milestones, not on a calendar — see [ROADMAP.md](https://github.com/constle/constle/blob/main/ROADMAP.md). Early and solo-maintained; see [CONTRIBUTING.md](https://github.com/constle/constle/blob/main/CONTRIBUTING.md). The most useful contributions right now are bug reports, a gVisor sandbox backend, and anything that closes a row in [Known limitations](#known-limitations).

Security issues: please don't open a public issue — see [SECURITY.md](https://github.com/constle/constle/blob/main/SECURITY.md).

## License

[Apache 2.0](https://github.com/constle/constle/blob/main/LICENSE)

---

**[github.com/constle/constle](https://github.com/constle/constle)** · **[docs.constle.dev](https://docs.constle.dev)**
