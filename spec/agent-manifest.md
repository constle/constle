# Constle AgentManifest Specification

**Spec version:** 0.1.0
**apiVersion:** `constle.dev/v1alpha1`
**Status:** Draft. Field names and semantics may change before v1.0.
**Last updated:** 2026-08-16
**Source of truth:** `pkg/manifest/manifest.go` and `pkg/manifest/parser.go`
**Annotated reference file:** [`spec/agent-manifest.yaml`](agent-manifest.yaml)
**Canonical URL:** https://constle.dev/spec/agent-manifest

---

## 1. Overview

The AgentManifest (also called the **Agentfile**) is a YAML file that tells the
Constle runtime everything it needs to know about an AI agent: who the agent
is, how to run it in isolation, what it may reach on the network, which MCP
servers and peer agents it may talk to, how much it may spend, when it must
stop and ask a human, and what to log.

The analogy is a Dockerfile. A developer writes one Agentfile and the Constle
runtime executes it the same way on any supported backend.

**Core design rule:** the manifest declares what the agent *needs*, not how to
implement it. The runtime makes the infrastructure decisions.

### 1.1 Relationship to `agent-manifest.yaml`

Two documents describe this format, and they are not redundant:

| File | Role |
|------|------|
| `spec/agent-manifest.md` (this document) | The normative specification. Full prose for every field: type, default, validation rules, enforcement status, and the reasoning behind the design. |
| `spec/agent-manifest.yaml` | An executable annotated reference file. It parses and passes `constle validate` against the current runtime. |

Where the two disagree, this document is normative and the discrepancy is a
bug. The YAML file is kept executable precisely so that drift is detectable:

```console
$ constle validate spec/agent-manifest.yaml
```

### 1.2 The rule this specification is written under

> **A declared protection must never look real when it isn't.**

This principle governs the entire format, and it is why the enforcement labels
in §2.2 exist and are applied pedantically. A field that is parsed but not
acted upon is labelled as such, in this document and — where the runtime can
detect it — in a warning printed by `constle validate` and `constle run`.
Constle would rather tell an operator that a guardrail is inert than let them
believe in one that isn't.

---

## 2. Conventions

### 2.1 Required vs. optional

A field marked **required** causes the runtime to reject the manifest if it is
absent or empty. A field marked **optional** may be omitted; where a default
exists, it is documented and applied at parse time.

Some fields are **conditionally required** — required only when another field
is present. These are listed in full in §16.

### 2.2 Enforcement labels

Every field carries exactly one label:

| Label | Meaning |
|-------|---------|
| **ENFORCED** | The runtime actively prevents violations at execution time. If the agent violates the constraint, the runtime blocks the action or stops the run. |
| **VALIDATED** | The runtime checks the value is well-formed and internally consistent at parse/validate time, and rejects the manifest if not. It does not constrain behaviour during execution. |
| **DECLARED** | The value is parsed, defaulted, and carried through (displayed, logged, or exported), but no code path changes behaviour based on it. Enforcement may be planned; it does not exist today. |
| **INFORMATIONAL** | The runtime does not read the field at all. It exists for humans and external tooling. |

The distinction between DECLARED and ENFORCED is the most important thing in
this document. **If a field is DECLARED, you cannot rely on the runtime to stop
the agent from violating it.** A DECLARED security field is documentation, not
a control.

### 2.3 Where enforcement happens

Every enforcement point in Constle sits **outside the sandbox**, at a
chokepoint the agent's traffic must physically traverse:

| Chokepoint | Enforces |
|------------|----------|
| Squid egress proxy (per run) | `sandbox.network.allowed_hosts` |
| MCP gate proxy (per run) | `mcp.servers[].tools`, `human_gates.*`, `spending.*` metering |
| A2A gate + host listener (per run) | `a2a.peers` authorization, envelope signing and verification |
| Supervisor process | `limits.max_duration_seconds`, `sandbox.memory_mb` |

This is not an implementation detail — it is the reason certain intuitively
desirable fields do not exist. Constle assumes nothing inside the sandbox is
trustworthy. A control that depended on the agent truthfully announcing its own
behaviour would be reliable only while it was unnecessary. See §13.3 for the
worked example (filesystem write gating).

---

## 3. Document structure

```yaml
apiVersion: constle.dev/v1alpha1   # required
kind: AgentManifest                # required

identity: ...      # who the agent is, and its cryptographic identity
sandbox: ...       # how to run and isolate it
capabilities: ...  # declared action classes; drives isolation inference
mcp: ...           # MCP servers reachable through the gate proxy
a2a: ...           # signed agent-to-agent peers
spending: ...      # cost caps, metered at the MCP gate
limits: ...        # hard runtime constraints
human_gates: ...   # when to pause for human approval
compliance: ...    # audit and regulatory metadata
metadata: ...      # descriptive only
```

All sections except `apiVersion`, `kind`, and `identity.name` are optional.

---

## 4. Top-level fields

### 4.1 `apiVersion`

| | |
|-|-|
| Type | string |
| Required | yes |
| Valid values | `constle.dev/v1alpha1` |
| Enforcement | VALIDATED |

The schema version of this manifest. Must be exactly `constle.dev/v1alpha1`;
any other value is rejected with an error naming the expected value.

The `v1alpha1` suffix is a promise about stability, not a version of Constle
itself: see §15.

### 4.2 `kind`

| | |
|-|-|
| Type | string |
| Required | yes |
| Valid values | `AgentManifest` |
| Enforcement | VALIDATED |

The resource type. Must be exactly `AgentManifest`. The field exists so that
future resource types (for example a separately-distributed `AgentPolicy`) can
share the same file convention without ambiguity.

---

## 5. Section: `identity`

Who this agent is, and — optionally — the cryptographic identity that signs its
audit log and its agent-to-agent traffic.

```yaml
identity:
  name: "invoice-processor"
  version: "1.2.0"
  owner: "finance@company.com"
  did: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99mXQkL3vUbEr8W3hosJqFr"
```

### 5.1 `identity.name`

| | |
|-|-|
| Type | string |
| Required | **yes** |
| Enforcement | VALIDATED |

Human-readable name for the agent. It identifies the agent in `constle ps`,
`constle stop`, every audit log entry, and the on-disk identity directory
(`~/.constle/identities/<name>/`). Must be non-empty.

Recommended format is lowercase with hyphens. The name is not a security
boundary: it is not unique across machines, and nothing is authorized on the
basis of it. When you need an identifier that cannot be forged or reassigned,
that is `identity.did`.

### 5.2 `identity.version`

| | |
|-|-|
| Type | string |
| Required | optional |
| Recommended format | semver, e.g. `1.0.0` |
| Enforcement | DECLARED |

The version of this agent's own code and configuration — not the version of the
manifest schema (that is `apiVersion`) and not the version of this
specification.

It is displayed by `constle validate` and carried into run output. Its value is
in incident reconstruction: when an audit log shows an agent behaving oddly on
a given day, `version` is what tells you which build produced it.

### 5.3 `identity.owner`

| | |
|-|-|
| Type | string |
| Required | optional |
| Enforcement | VALIDATED — conditionally ENFORCED (see below) |

Email address or identifier of the human accountable for this agent.

When the agent has a DID identity **and** the stored identity records an owner
**and** both values are non-empty, they must match: a run whose Agentfile
declares a different owner than `~/.constle/identities/<name>/identity.json`
is refused. The check is an equality comparison, and it only binds when both
sides are populated — it is a guard against an Agentfile drifting away from
the identity it claims, not an authorization system.

Without an owner, attribution in a compliance review is guesswork. Set it.

### 5.4 `identity.did`

| | |
|-|-|
| Type | string |
| Required | optional |
| Valid values | a `did:key` identifier encoding an Ed25519 public key |
| Enforcement | ENFORCED |

The agent's cryptographic identity: a
[`did:key`](https://w3c-ccg.github.io/did-method-key/) identifier that
self-describes an Ed25519 public key, base58btc-encoded (`did:key:z…`).

Create one with:

```console
$ constle identity create my-agent
```

and paste the printed DID here.

**Only the public DID appears in the manifest.** The private key lives at
`~/.constle/identities/<name>/key.pem` (mode 0600, in a 0700 directory) and
never enters the Agentfile, the audit log, or the sandbox — the same
indirection principle as `human_gates.notify[].url_secret_ref`.

**`did:key` is the only supported method.** It is self-describing: the
verification key is recovered from the identifier string alone, so there is no
resolution step, no registry, and no network dependency in the trust path.
Other methods are rejected at validate time. See §21 for why `did:web` and
`did:constle` are deliberately not supported yet.

When `did` is set, three things become true:

1. **Every audit log entry is signed and hash-chained.** Each JSONL entry
   carries `did`, `prev_hash` (SHA-256 of the previous raw line), and `sig`
   (Ed25519 over the entry with `sig` absent). `constle audit verify` checks
   every signature and the whole chain, and reports the exact line and kind of
   tampering — `invalid_signature`, `chain_break_missing_entry`,
   `chain_break_reordered`, or `did_mismatch`.
2. **`constle run` fails closed.** The run refuses to start if the matching
   private key is missing, unreadable, has permissions other than exactly 0600,
   or derives a DID different from the one declared. A declared identity must
   never look real when it isn't. `constle validate` warns rather than fails,
   since validation is not execution.
3. **Identity-scoped features unlock.** `spending.max_per_day_usd` and any
   `a2a` configuration require a DID and are rejected without one.

Full design: [`spec/identity.md`](identity.md).

---

## 6. Section: `sandbox`

How Constle runs and isolates the agent.

```yaml
sandbox:
  isolation: network
  image: "python:3.11-slim"
  command: ["python", "/workspace/agent.py"]
  memory_mb: 512
  disk_mb: 2048
  network:
    egress: restricted
    allowed_hosts:
      - "api.anthropic.com"
```

### 6.1 `sandbox.isolation`

| | |
|-|-|
| Type | string |
| Required | optional |
| Valid values | `none`, `process`, `network`, `kernel` |
| Default | inferred from `capabilities` |
| Enforcement | ENFORCED (backend selection) |

The isolation level this agent requires. When omitted, the runtime infers the
minimum sufficient level from `capabilities` (§7) and always picks the
strongest level any declared capability requires. `constle validate` prints the
level it resolved.

| Level | What it provides | Use when |
|-------|-----------------|----------|
| `none` | No isolation. Development only. | Local testing, never production |
| `process` | Process-level separation from the host | Agent only reads or writes local files |
| `network` | Network and process isolation | Agent makes outbound calls |
| `kernel` | Hardware-level isolation via a Firecracker microVM | Agent can move money, delete data, or spawn sub-agents |

The runtime selects the strongest **available** backend that satisfies the
requirement. When the required level cannot be provided on this machine —
Firecracker requires KVM and root — the runtime says so explicitly rather than
silently downgrading, because a silent downgrade is precisely a protection that
looks real when it isn't.

### 6.2 `sandbox.image`

| | |
|-|-|
| Type | string |
| Required | optional in the schema; required in practice by both backends |
| Enforcement | ENFORCED |

The container image to run. The Docker backend pulls and runs it directly; the
Firecracker backend resolves it to a rootfs.

`Validate()` does not reject a manifest without an image, because a manifest
can legitimately be validated for its policy content alone. A run without an
image fails at the backend.

```yaml
image: "python:3.11-slim"
image: "ghcr.io/myorg/myagent:v1.2.0"
```

Pin a digest or an immutable tag for anything you care about. A mutable tag
means the thing you audited and the thing that runs are only incidentally the
same.

### 6.3 `sandbox.command`

| | |
|-|-|
| Type | list of strings |
| Required | optional |
| Default | the image's own CMD |
| Enforcement | ENFORCED |

The command to run inside the sandbox, passed through as the container command.
Exec form only — a list of arguments, not a shell string. There is no shell
interpolation.

```yaml
command: ["python", "/workspace/agent.py"]
```

### 6.4 `sandbox.memory_mb`

| | |
|-|-|
| Type | integer |
| Required | optional |
| Default | `512` |
| Unit | megabytes |
| Enforcement | ENFORCED |

Maximum RAM available to the agent. The Docker backend passes it as the
container memory limit; the Firecracker backend sizes the microVM with it. In
both cases the limit is imposed from outside the sandbox and the agent cannot
raise it. Exceeding it kills the workload.

### 6.5 `sandbox.disk_mb`

| | |
|-|-|
| Type | integer |
| Required | optional |
| Default | `2048` |
| Unit | megabytes |
| Enforcement | **DECLARED** |

Intended maximum writable disk space. **Parsed and defaulted, but not applied
by either backend today.** An agent can currently fill the host disk regardless
of this value. Treat it as documentation of intent until it moves to ENFORCED.

---

## 7. Section: `sandbox.network`

What the agent may reach on the network. With the MCP gate, this is the most
security-critical part of the manifest.

```yaml
sandbox:
  network:
    egress: restricted
    allowed_hosts:
      - "api.anthropic.com"
      - "arxiv.org"
```

### 7.1 `sandbox.network.egress`

| | |
|-|-|
| Type | string |
| Required | optional |
| Valid values | `restricted`, `open`, `none` |
| Default | `restricted` |
| Enforcement | **DECLARED** |

Intended egress policy mode.

**This field is not enforced.** It is parsed and defaulted, but no code path
reads it. Egress is governed entirely by `allowed_hosts` below: the sandbox has
no default gateway, and every outbound connection must pass the proxy
allowlist. Setting `egress: open` does **not** open the network — an agent with
`egress: open` and an empty `allowed_hosts` reaches nothing at all.

The field is retained because the split between a policy mode and the allowlist
is expected to become real, and removing it now would break existing files.
Until then, do not reason about network exposure from this value; read
`allowed_hosts`.

### 7.2 `sandbox.network.allowed_hosts`

| | |
|-|-|
| Type | list of strings |
| Required | optional (an empty list means no egress) |
| Enforcement | **ENFORCED** |

The allowlist from which the per-run egress proxy is built. This is the field
that actually constrains the network. Everything not listed is refused.

```yaml
allowed_hosts:
  - "api.anthropic.com"
  - ".example.com"        # matches example.com and all subdomains
```

Entries are hostnames. An entry beginning with `.` matches that domain and all
its subdomains; otherwise the match is exact. Ports, schemes, paths, and IP
literals are not part of the matching.

**How it is enforced.** The agent's sandbox is attached only to an internal
network with no route to the internet. A per-run Squid proxy is the sole
bridge, and it enforces the allowlist. On the Firecracker backend the same
proxy runs on the host, with nftables restricting the guest to it. Enforcement
is at the OS network layer: the agent cannot bypass it by unsetting proxy
environment variables or dialling an IP directly, because there is no route.

Blocked attempts are recorded as `network_blocked` audit events; permitted ones
as `network_allowed`.

**Two entries are rejected at validate time** rather than silently accepted,
because each would open a bypass around a stronger control:

1. **Any host that also appears under `mcp.servers[].url` or
   `a2a.peers[].endpoint`.** Allowlisting it would let the agent reach that
   server or peer directly, bypassing the gate proxy that enforces tool
   allowlists, human gates, spending metering, and A2A signing. MCP and A2A
   traffic is routed through the gate automatically; it must not — and need
   not — appear here.
2. **`localhost`, `127.0.0.1`, `::1`, or `host.docker.internal`, when `mcp` or
   `a2a` are declared.** These name the sandbox's host, which is where the gate
   transport listens. Allowlisting them wholesale would expose the gate itself
   and every other host service to the agent.

Both are errors, not warnings. A bypass that is merely warned about is a bypass.

---

## 8. Section: `capabilities`

A flat list of strings naming the classes of action this agent performs.

```yaml
capabilities:
  - read_file
  - write_file
  - web_search
  - external_api
  - send_email
```

| | |
|-|-|
| Type | list of strings |
| Required | optional |
| Enforcement | ENFORCED for isolation inference; DECLARED otherwise |

This is the complete set of recognised values. An unrecognised entry is a
**validation error**, not a warning — a typo'd capability must not silently
lower the inferred isolation level.

| Value | Meaning | Minimum isolation |
|-------|---------|-------------------|
| `read_file` | Read files | `process` |
| `write_file` | Write files | `process` |
| `web_search` | Outbound HTTP for search | `network` |
| `external_api` | Call external APIs | `network` |
| `send_email` | Send email | `network` |
| `spawn_subagent` | Start another agent | `kernel` |
| `external_transfer` | Move money or financial assets | `kernel` |
| `delete_records` | Permanently delete data | `kernel` |

The list drives exactly two things, and nothing else:

**1. Isolation inference (ENFORCED).** When `sandbox.isolation` is omitted, the
runtime selects the strongest level any declared capability requires. An agent
declaring `[web_search, external_transfer]` gets `kernel`, because
`external_transfer` demands it.

**2. Advisory gate reporting (DECLARED).** Capabilities naming an irreversible
action — `send_email`, `spawn_subagent`, `external_transfer`, `delete_records`
— are reported by `constle validate` as requiring approval. **This is advice,
not enforcement.** Declaring `send_email` here gates nothing on its own.
Enforcement happens only through `human_gates.require_approval_for` (§11),
which matches MCP tool names.

### 8.1 What `capabilities` is not

It is not a sandbox permission system. Declaring `read_file` does not grant
file access, and omitting it does not remove it — the agent's actual filesystem
access comes from the image and the mounts, not from this list. Nothing at
runtime blocks an undeclared action on the basis of its absence here.

Note also the shape of the document: `capabilities` is a flat list of strings,
and `mcp:` and `a2a:` are **separate top-level keys**, not nested under it.
They are independent wiring with their own validators; nothing reads them
through this list.

---

## 9. Section: `mcp`

The Model Context Protocol servers this agent may call.

```yaml
mcp:
  servers:
    - id: web-search
      url: "https://mcp-search.example.com/mcp"
      tools: ["search"]
      pricing:
        meters:
          - usage_path: "result.usage.input_tokens"
            usd_per_unit: "0.00000300"
          - usage_path: "result.usage.output_tokens"
            usd_per_unit: "0.00001500"
```

Every declared server is reachable **only** through the Constle gate proxy — a
protocol-aware chokepoint, the MCP analogue of the HTTP egress proxy. The agent
receives `CONSTLE_MCP_<ID>_URL` pointing at the gate; the real URL never enters
the sandbox, and the sandbox network blocks every direct path to it (§7.2).

The gate is what makes tool allowlists, human gates, and spending metering
enforceable: the call must physically traverse it.

### 9.1 `mcp.servers[].id`

| | |
|-|-|
| Type | string |
| Required | **yes** |
| Charset | lowercase letters, digits, `-`, `_` |
| Enforcement | VALIDATED |

A unique local identifier for this server. It names the environment variable
the agent reads (`web-search` → `CONSTLE_MCP_WEB_SEARCH_URL`: hyphens become
underscores, uppercased) and appears in audit events. Must be unique across
servers; duplicates are rejected.

### 9.2 `mcp.servers[].url`

| | |
|-|-|
| Type | string |
| Required | **yes** |
| Valid schemes | `http`, `https` |
| Enforcement | ENFORCED (host-side only) |

The real endpoint of the MCP server. Streamable HTTP is the only supported MCP
transport, so other schemes are rejected. The URL must have a host.

This value is **host side only**. It is never forwarded into the sandbox, and
its host must not appear in `allowed_hosts` (§7.2).

### 9.3 `mcp.servers[].tools`

| | |
|-|-|
| Type | list of strings |
| Required | optional |
| Default | empty — every tool is allowed through |
| Enforcement | **ENFORCED** |

An allowlist of tool names the agent may call on this server. When present, a
`tools/call` naming anything else is refused at the gate and recorded as an
`mcp_tool_blocked` audit event. When omitted, every tool passes through —
gated tools (§11) still gate.

Declaring the allowlist is worth the effort: it converts "this server exposes
40 tools and the agent probably only uses 2" from a trust assumption into an
enforced fact.

### 9.4 `mcp.servers[].pricing`

| | |
|-|-|
| Type | object with a `meters` list |
| Required | optional |
| Enforcement | **ENFORCED** |

When present, the gate proxy meters **every** `tools/call` response from this
server and charges it against the caps in `spending` (§10).

**Pricing is deliberately server-wide.** A priced server cannot expose an
"unpriced" tool: a response missing a declared usage value is a *metering
failure* that kills the run (fail closed), because a server that could omit its
usage field could zero its own bill. To mix free and priced tools from one
upstream, declare its URL twice under two ids with disjoint `tools`
allowlists — one priced, one not.

Pricing is always declared here by the operator, never guessed or hardcoded per
provider, so the metering code stays generic and auditable.

A `pricing` block with an empty `meters` list is rejected: it could not measure
anything, and would read as "priced" while metering nothing.

#### `pricing.meters[].usage_path`

| | |
|-|-|
| Type | string |
| Required | **yes** |
| Enforcement | VALIDATED (syntax), ENFORCED (extraction) |

A dot-separated path into the **full JSON-RPC response message**, locating one
usage number. A digit segment indexes an array:
`result.content.0.usage.input_tokens`.

There are no wildcards. The path is an exact, deterministic contract — the same
principle as exact tool-name matching for gates. A pattern language here would
mean the bill depended on a fuzzy match.

#### `pricing.meters[].usd_per_unit`

| | |
|-|-|
| Type | string (exact decimal) |
| Required | **yes** |
| Precision | at most 8 decimal places (1e-8 USD) |
| Enforcement | VALIDATED (parse), ENFORCED (charge) |

The price of one usage unit, as a decimal **string**, never a YAML float.
Floats cannot represent decimal money exactly, and a rounding error in a
spending cap is a security bug, not a cosmetic one. Internally all money is
integer micro-cents.

The cost of one response is the **sum over all meters** — a list, because real
API pricing rates input and output units differently.

---

## 10. Section: `a2a`

Signed agent-to-agent communication with explicitly declared peers.

```yaml
a2a:
  listen: ":9443"
  peers:
    - name: summarizer
      did: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H99mXQkL3vUbEr8W3hosJqFr"
      endpoint: "https://summarizer.example.net/a2a"
```

Every peer is declared by the operator, with its DID and endpoint exchanged out
of band. **There is deliberately no discovery mechanism.** An agent can only
ever exchange A2A calls with peers written into this file — it cannot find,
resolve, or be introduced to a peer it was not already configured to know
about. That is a scope decision, not a gap.

All A2A traffic is signed and verified **in the host Constle process** using
this agent's identity, so `identity.did` is required. The sandbox never signs,
never verifies, and never learns a peer's real endpoint: it talks only to the
per-run gate at `CONSTLE_A2A_URL`.

Full design, including the inbound listener hardening, envelope format, and the
named replay-protection limitation: [`spec/a2a.md`](a2a.md).

### 10.1 `a2a.listen`

| | |
|-|-|
| Type | string (`host:port` or `:port`) |
| Required | optional |
| Enforcement | ENFORCED |

The host-side address on which this agent's Constle process accepts inbound
calls from declared peers. Omit it for outbound-only agents.

The listener runs on the **host**, never in the sandbox. It relays a call
inward only after the call passes signature verification *and* its sender DID
appears in `peers`. Verified calls are parked in a bounded per-peer inbox that
the agent drains over a connection it initiates.

**Declaring `listen` without `peers` is an error.** No sender could ever be
authorized, so the listener could only ever reject — a configuration that looks
like connectivity and provides none.

### 10.2 `a2a.peers[].name`

| | |
|-|-|
| Type | string |
| Required | **yes** |
| Charset | lowercase letters, digits, `-`, `_` |
| Enforcement | VALIDATED |

A local alias for the peer, used in gate URLs and audit events. Must be unique.
This is the only way the sandbox can name a peer — it posts to
`$CONSTLE_A2A_URL/send/<name>`, and an undeclared name is rejected at the gate
with a 403. Nothing in the sandbox can name an endpoint.

### 10.3 `a2a.peers[].did`

| | |
|-|-|
| Type | string (`did:key`) |
| Required | **yes** |
| Enforcement | **ENFORCED** |

The peer's `did:key` identifier. The verification key for every message to and
from this peer is recovered from this string alone — no registry, no resolution
service.

Rejected at validate time: a malformed DID, two peers declaring the same DID
(sender identity would be ambiguous), and a peer DID equal to this agent's own
`identity.did`.

### 10.4 `a2a.peers[].endpoint`

| | |
|-|-|
| Type | string (URL) |
| Required | **yes** |
| Valid schemes | `http`, `https` |
| Enforcement | ENFORCED (host-side only) |

The peer's public A2A URL — its host process's `a2a.listen` address. Host side
only; never forwarded into the sandbox, and its host must not appear in
`allowed_hosts` (§7.2).

---

## 11. Section: `spending`

Cost guardrails, enforced against traffic metered at the MCP gate.

```yaml
spending:
  max_per_run_usd: "0.50"
  max_per_day_usd: "5.00"
  max_per_month_usd: "50.00"
  alerts:
    warn_at_pct_of_daily: 80
```

### 11.1 Enforcement scope — read this before relying on a cap

Limits are enforced against cost **metered at the MCP gate proxy, for servers
that declare a `pricing` block** (§9.4). Nothing else is metered.

In particular, traffic through `sandbox.network.allowed_hosts` is **not**
metered. Constle refuses to TLS-intercept it: doing so would let the runtime
read everything the agent says to every allowlisted host, which is far beyond
what cost metering needs. The consequence is stated plainly rather than hidden:
a limit declared without a priced MCP server measures nothing at all.

`constle validate` and `constle run` warn explicitly in each of these cases:

| Situation | Warning |
|-----------|---------|
| Limits declared, no priced MCP server | Limits are **not enforced** — nothing to meter |
| Limits declared, priced servers present, `allowed_hosts` non-empty | Limits cover only the priced servers; `allowed_hosts` traffic is unmetered |
| Priced servers present, no limits declared | Usage is metered but nothing is enforced |
| `max_per_month_usd` declared | Not enforced by this version |

### 11.2 Amount format

All amounts are exact decimal **strings**, never YAML floats, for the reason
given in §9.4. A cap of `"0"` is **rejected as ambiguous** — at enforcement
time a zero cap would read as "unset", so the manifest must say which it means:
omit the field to leave a limit unset.

### 11.3 `spending.max_per_run_usd`

| | |
|-|-|
| Type | string (exact decimal) |
| Required | optional |
| Enforcement | **ENFORCED** |

Hard cap on metered cost for a single run. Crossing it trips the gate and kills
the run through the same path as `limits.max_duration_seconds`, recording a
`spending_limit_reached` audit event naming `max_per_run_usd`.

The cap trips when the running total **exceeds** it. Because metering is
post-hoc — a response's cost is only knowable once the response has arrived —
the charge that crosses the cap is still incurred and still recorded. The
ledger records reality; enforcement stops what happens next.

### 11.4 `spending.max_per_day_usd`

| | |
|-|-|
| Type | string (exact decimal) |
| Required | optional |
| Requires | `identity.did` |
| Enforcement | **ENFORCED** |

Hard cap per UTC calendar day, tracked durably across runs in
`~/.constle/spending/<did>/` under a file lock, so concurrent runs of the same
identity share one ledger.

**It requires `identity.did` and is rejected without one.** Keying the ledger
by name would let a rename reset the tracking, which is not a cap.

Two behaviours follow from durability:

- A run whose accumulated daily spend already meets or exceeds the cap is
  **refused before the sandbox starts**, with a `spending_limit_reached` event
  recording `action: run_refused`. Starting it would guarantee an overshoot,
  since the kill can only land after a charge is metered.
- An unreadable ledger is a hard error, never treated as `$0` spent.

### 11.5 `spending.max_per_month_usd`

| | |
|-|-|
| Type | string (exact decimal) |
| Required | optional |
| Enforcement | **DECLARED** |

**Not enforced by this version.** The value is parsed and validated, but no
monthly ledger exists. Declaring it produces an explicit warning rather than
silent false assurance.

### 11.6 `spending.alerts.warn_at_pct_of_daily`

| | |
|-|-|
| Type | integer, 1–100 |
| Required | optional |
| Requires | `spending.max_per_day_usd` |
| Enforcement | **ENFORCED** (non-blocking) |

Writes a one-time `spending_limit_reached` warning to the audit log when the
day's total first crosses this percentage of `max_per_day_usd`. It never blocks
a call — it is a signal, not a control.

The threshold comparison is exact (cross-multiplied in arbitrary precision), so
it cannot drift or overflow. Setting it without `max_per_day_usd` is an
error: there would be no cap to warn about.

---

## 12. Section: `limits`

Hard runtime constraints.

```yaml
limits:
  max_duration_seconds: 300
```

### 12.1 `limits.max_duration_seconds`

| | |
|-|-|
| Type | integer |
| Required | optional |
| Default | `0` (no limit) |
| Unit | seconds |
| Enforcement | **ENFORCED** |

Maximum wall-clock run time. On expiry the runtime stops the sandbox and
records a `terminated_by_limit` audit event. `0` or omitted means no limit.

This is a supervisor-side timer, not a request the agent can decline.

---

## 13. Section: `human_gates`

When the agent must stop and ask a human.

```yaml
human_gates:
  enabled: true
  require_approval_for:
    - "send_email"
  approval_timeout_seconds: 300
  on_timeout: abort
  notify:
    - channel: webhook
      url_secret_ref: "HUMAN_GATE_WEBHOOK_URL"
```

Human gates are the primary defense against an agent being talked into a
consequential action — by a prompt injection, a poisoned document, or its own
misjudgement.

### 13.1 `human_gates.enabled`

| | |
|-|-|
| Type | boolean |
| Required | optional |
| Default | `false` |
| Enforcement | **ENFORCED** |

The master switch. When `false`, **no gating occurs at all**, even if
`require_approval_for` lists entries. Set it to `true` for any agent whose
gates you intend to rely on.

### 13.2 `human_gates.require_approval_for`

| | |
|-|-|
| Type | list of strings — **MCP tool names** |
| Required | optional |
| Enforcement | **ENFORCED** for entries matching a declared MCP tool |

**Mapping contract:** an entry gates a call when it is an **exact,
case-sensitive match** for the tool name — the `params.name` of a `tools/call`
request — on any server declared under `mcp.servers`. The tool name is the only
protocol-level identifier the gate proxy observes, and exact match is the only
deterministic, auditable mapping. There is no semantic guessing and no pattern
syntax.

When a gated call arrives, the gate pauses it, emits a `gate_triggered` audit
event, notifies any configured webhook, and waits for a decision — recorded as
`gate_approved`, `gate_denied`, or `gate_timeout`.

**Entries that cannot match are reported, not silently ignored.** An entry that
provably matches no tool on any declared server is surfaced as a warning at
both validate and run time, stating that those calls will run *without*
approval. An entry is treated as possibly-enforced when any declared server
omits its `tools` allowlist, since the runtime match is against the actual tool
name of every call.

Note the consequence: **with no `mcp.servers` declared, nothing is gated**, and
Constle says so.

### 13.3 Why there is no `{action, paths, condition}` form

Gating a filesystem write — "require approval for writes under
`/workspace/output`" — cannot be expressed here, and the reason is
architectural rather than a missing feature. It is worth stating in full,
because the omission otherwise looks like an oversight.

Constle's core assumption is that nothing inside the sandbox is trusted. If the
agent is compromised, anything it reports about its own behaviour is
attacker-controlled. A gate that depended on the sandbox announcing "I am about
to write this path" would be exactly the wrong shape: **reliable only while it
was unnecessary.**

Every gate that exists today is enforced at a chokepoint *outside* the sandbox.
The MCP gate proxy sees the tool call because the call must physically traverse
it. The egress proxy sees the connection for the same reason.

File writes have no such external chokepoint yet. Enforcing on them requires
host-side observation of the filesystem — a watcher standing in the same
relation to writes as the proxy does to network traffic. That component does
not exist. Until it does, a `paths`/`condition` field could only be implemented
by trusting the sandbox, so it is **absent by design rather than unimplemented
by accident**.

### 13.4 `human_gates.approval_timeout_seconds`

| | |
|-|-|
| Type | integer |
| Required | optional |
| Default | `300` |
| Enforcement | **ENFORCED** |

How long a gated call waits for a decision before `on_timeout` applies. A
negative value is rejected.

When stdin is not a terminal — a backgrounded run, a pipe, CI — no human can
answer, so the gate says so once and simply waits for the deadline, letting
`on_timeout` decide. It does not block forever on a read that can never
resolve, and it does not silently treat "nobody is watching" as approval.

### 13.5 `human_gates.on_timeout`

| | |
|-|-|
| Type | string |
| Required | optional |
| Valid values | `abort`, `proceed` |
| Default | `abort` |
| Enforcement | **ENFORCED** |

| Value | Behaviour |
|-------|-----------|
| `abort` | The gated call is refused and the run stops. The safe default. |
| `proceed` | The call continues without approval. |

There is deliberately no `retry`. Use `abort`: an agent that proceeds without
approval after a timeout has a gate that reduces to a delay.

### 13.6 `human_gates.notify`

| | |
|-|-|
| Type | list of `{channel, url_secret_ref}` |
| Required | optional |
| Supported channels | `webhook` |
| Enforcement | **ENFORCED** |

Where to signal that a gate has triggered. **An unsupported channel is a
validation error, not a warning** — a declared notification path must never
look real when it isn't. A `webhook` entry without `url_secret_ref` is
likewise rejected.

`url_secret_ref` names the **environment variable** holding the webhook URL,
keeping the secret out of the committed manifest — the same indirection as
`identity.did` keeping the private key out.

Delivery is fire-and-forget: the gate never blocks on a notification, and a
failed delivery never blocks the approval flow. The local prompt and timeout
are the enforcement; the webhook is the signal. An unset environment variable
produces a visible warning and the gate still enforces locally.

---

## 14. Section: `compliance`

Regulatory and audit metadata.

```yaml
compliance:
  audit_log_level: standard
  frameworks:
    - "EU_AI_ACT"
    - "SOC2_TYPE2"
  geo_restrictions:
    allowed_regions: []
    denied_regions: []
```

### 14.1 `compliance.audit_log_level`

| | |
|-|-|
| Type | string |
| Required | optional |
| Valid values | `none`, `minimal`, `standard`, `verbose` |
| Default | `standard` |
| Enforcement | **DECLARED** |

**Not enforced.** The value is parsed and defaulted, but no code path varies
logging on it — audit output is identical at every level today, and setting
`none` does not disable the audit log.

### 14.2 `compliance.frameworks`

| | |
|-|-|
| Type | list of strings |
| Required | optional |
| Enforcement | **INFORMATIONAL** |

Regulatory frameworks the deployment is meant to satisfy. Descriptive metadata
for external policy engines, auditors, and registries. Constle neither
validates the names nor changes behaviour based on them.

Common values: `EU_AI_ACT`, `SOC2_TYPE2`, `ISO27001`, `HIPAA`, `PCI_DSS`.

### 14.3 `compliance.geo_restrictions`

| | |
|-|-|
| Type | object with `allowed_regions` and `denied_regions` string lists |
| Required | optional |
| Enforcement | **INFORMATIONAL** |

Region identifiers where the agent may or may not run. Parsed and carried
through for downstream tooling. **Constle does not determine its own region and
cannot refuse to run on this basis.** These lists constrain nothing today.

---

## 15. Section: `metadata`

Descriptive fields, never read by the runtime when making execution decisions.
All **INFORMATIONAL**.

```yaml
metadata:
  description: "Processes invoices and routes them to the approval queue."
  author: "finance-team@company.com"
  license: "Apache-2.0"
  labels:
    team: "finance"
    cost_center: "cc-1042"
    environment: "production"
```

| Field | Type | Notes |
|-------|------|-------|
| `description` | string | What this agent does, for humans |
| `author` | string | Email, DID, or handle |
| `license` | string | SPDX identifier for the agent's code |
| `labels` | map of string to string | Arbitrary key/value pairs for cost allocation, ownership, environment tagging. No enforced key names or formats. |

---

## 16. Cross-field validation rules

These rules involve more than one field, and all of them are **errors**, not
warnings. Each closes a path where a declared control could be silently
inert or bypassed.

| Rule | Rationale |
|------|-----------|
| `spending.max_per_day_usd` requires `identity.did` | The daily ledger is keyed by DID; keying by name would let a rename reset it |
| `spending.alerts.warn_at_pct_of_daily` requires `max_per_day_usd` | No cap to warn about |
| A spending cap of `"0"` is rejected | Ambiguous between "no spending allowed" and "unset" |
| `a2a.*` requires `identity.did` | Every A2A call is signed with the agent's identity |
| `a2a.listen` requires a non-empty `a2a.peers` | No sender could ever be authorized |
| Peer DIDs must be unique, and none may equal `identity.did` | Sender identity would be ambiguous |
| `mcp.servers[].id` and `a2a.peers[].name` must be unique and match the id charset | They are embedded in env var names, gate URLs, and audit events |
| An MCP server URL host must not appear in `allowed_hosts` | Would bypass the gate proxy |
| An A2A peer endpoint host must not appear in `allowed_hosts` | Would bypass the signing gate |
| Host loopback aliases must not appear in `allowed_hosts` when `mcp` or `a2a` are declared | Would expose the gate transport and other host services |
| An `mcp.servers[].pricing` block must declare at least one meter | Would read as priced while metering nothing |
| `human_gates.notify[].channel` must be `webhook`, with a `url_secret_ref` | A declared notification path must never look real when it isn't |
| An unrecognised capability is rejected | A typo must not silently lower inferred isolation |

Warnings — surfaced, but not fatal — cover the cases where a declaration is
well-formed but the runtime cannot act on it: unenforceable gate entries,
unmetered spending limits, `max_per_month_usd`, and an `identity.did` whose
private key is not available on this machine.

---

## 17. Enforcement summary

| Field | Enforcement | Notes |
|-------|-------------|-------|
| `apiVersion` | VALIDATED | Must be `constle.dev/v1alpha1` |
| `kind` | VALIDATED | Must be `AgentManifest` |
| `identity.name` | VALIDATED | Required; appears in all audit events |
| `identity.version` | DECLARED | Displayed and carried through |
| `identity.owner` | VALIDATED | Enforced as an equality check against the stored identity when both are set |
| `identity.did` | **ENFORCED** | Signs and chains the audit log; run fails closed without the local key |
| `sandbox.isolation` | **ENFORCED** | Inferred when absent; drives backend selection |
| `sandbox.image` | **ENFORCED** | Pulled and run by the backend |
| `sandbox.command` | **ENFORCED** | Passed as the container command |
| `sandbox.memory_mb` | **ENFORCED** | Container memory limit / microVM size |
| `sandbox.disk_mb` | DECLARED | Parsed and defaulted; not applied |
| `sandbox.network.egress` | DECLARED | Parsed and defaulted; **no code path reads it** |
| `sandbox.network.allowed_hosts` | **ENFORCED** | Per-run Squid allowlist; the real egress control |
| `capabilities` | **ENFORCED** (inference) / DECLARED (gate advice) | Unknown values rejected |
| `mcp.servers[].id` | VALIDATED | Unique; names `CONSTLE_MCP_<ID>_URL` |
| `mcp.servers[].url` | **ENFORCED** | Host side only; never enters the sandbox |
| `mcp.servers[].tools` | **ENFORCED** | Non-listed tools blocked at the gate |
| `mcp.servers[].pricing` | **ENFORCED** | Meters every `tools/call` response; fails closed on missing usage |
| `a2a.listen` | **ENFORCED** | Host-side listener; verifies before relaying inward |
| `a2a.peers[].name` | VALIDATED | The only peer reference the sandbox can name |
| `a2a.peers[].did` | **ENFORCED** | Verification key for every message |
| `a2a.peers[].endpoint` | **ENFORCED** | Host side only; never enters the sandbox |
| `spending.max_per_run_usd` | **ENFORCED** | Trips the gate and kills the run |
| `spending.max_per_day_usd` | **ENFORCED** | Durable per-DID ledger; refuses to start when exhausted |
| `spending.max_per_month_usd` | DECLARED | No monthly ledger exists; warned about |
| `spending.alerts.warn_at_pct_of_daily` | **ENFORCED** | One-time non-blocking audit warning |
| `limits.max_duration_seconds` | **ENFORCED** | Sandbox stopped; `terminated_by_limit` recorded |
| `human_gates.enabled` | **ENFORCED** | Master switch; `false` disables all gating |
| `human_gates.require_approval_for` | **ENFORCED** | Exact MCP tool-name match; unmatchable entries warned |
| `human_gates.approval_timeout_seconds` | **ENFORCED** | Default 300 |
| `human_gates.on_timeout` | **ENFORCED** | Default `abort` |
| `human_gates.notify` | **ENFORCED** | Webhook only; unsupported channel is an error |
| `compliance.audit_log_level` | DECLARED | Parsed and defaulted; logging does not vary |
| `compliance.frameworks` | INFORMATIONAL | Descriptive metadata |
| `compliance.geo_restrictions` | INFORMATIONAL | Constle cannot determine its own region |
| `metadata.*` | INFORMATIONAL | Never read for execution decisions |

---

## 18. Examples

### 18.1 Minimal

The smallest valid Agentfile that does something useful:

```yaml
apiVersion: constle.dev/v1alpha1
kind: AgentManifest

identity:
  name: "my-agent"

sandbox:
  image: "python:3.11-slim"
  command: ["python", "/workspace/agent.py"]
  network:
    allowed_hosts:
      - "api.anthropic.com"
```

Runs `python /workspace/agent.py` in a Python 3.11 container, blocks all
outbound traffic except to `api.anthropic.com`, applies no time limit, and
writes an unsigned audit log.

### 18.2 Full

A production-shaped manifest exercising every enforced control:

```yaml
apiVersion: constle.dev/v1alpha1
kind: AgentManifest

identity:
  name: "invoice-processor"
  version: "2.1.0"
  owner: "finance-team@company.com"
  did: "did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP"

sandbox:
  isolation: kernel
  image: "ghcr.io/myorg/invoice-agent:2.1.0"
  command: ["python", "main.py"]
  memory_mb: 1024
  network:
    allowed_hosts:
      - "arxiv.org"

capabilities:
  - read_file
  - write_file
  - external_api
  - send_email

mcp:
  servers:
    - id: erp
      url: "https://mcp-erp.example.com/mcp"
      tools: ["lookup_invoice", "post_payment"]
      pricing:
        meters:
          - usage_path: "result.usage.input_tokens"
            usd_per_unit: "0.00000300"
          - usage_path: "result.usage.output_tokens"
            usd_per_unit: "0.00001500"

    - id: email
      url: "https://mcp-email.example.com/mcp"
      tools: ["send_email"]

spending:
  max_per_run_usd: "0.50"
  max_per_day_usd: "10.00"
  alerts:
    warn_at_pct_of_daily: 80

limits:
  max_duration_seconds: 300

human_gates:
  enabled: true
  require_approval_for:
    - "post_payment"
    - "send_email"
  approval_timeout_seconds: 300
  on_timeout: abort
  notify:
    - channel: webhook
      url_secret_ref: "HUMAN_GATE_WEBHOOK_URL"

compliance:
  audit_log_level: verbose
  frameworks:
    - "EU_AI_ACT"
    - "SOC2_TYPE2"

metadata:
  description: >
    Reads incoming invoices, validates them against the ERP, and initiates
    payments. Human approval is required before every payment and every email.
  author: "finance-team@company.com"
  license: "Proprietary"
  labels:
    team: "finance"
    cost_center: "cc-1042"
    environment: "production"
```

Note what makes the gates in this example real: `post_payment` and `send_email`
are exact tool names declared under `mcp.servers[].tools`, so the gate proxy
matches and pauses them. Had they been written as capability names not exposed
by any declared server, `constle validate` would warn that they gate nothing.

---

## 19. Versioning and compatibility

### 19.1 Two version numbers

| Number | What it versions | Current |
|--------|-----------------|---------|
| **Spec version** | This document — its prose, structure, and accuracy | `0.1.0` |
| **`apiVersion`** | The wire format the runtime accepts | `constle.dev/v1alpha1` |

The spec version changes whenever this document changes materially, including
when a field's enforcement status changes without any change to the format. The
`apiVersion` changes only when the format itself changes incompatibly.

### 19.2 apiVersion progression

| apiVersion | Status | Meaning |
|------------|--------|---------|
| `constle.dev/v1alpha1` | **Current** | Unstable. Field names and semantics may change. |
| `constle.dev/v1beta1` | Planned | Stable field names. New fields may be added. |
| `constle.dev/v1` | Planned | Fully stable. Backward-compatible changes only. |

The runtime will support the previous `apiVersion` for at least one major
release after it is deprecated; a `v1beta1` runtime will run `v1alpha1`
manifests and record a deprecation warning.

### 19.3 What is a breaking change

A previously valid manifest being rejected, or behaving differently without
modification:

- renaming a field;
- changing a field's type;
- making an optional field required;
- removing a valid enum value;
- changing a default in a way that affects security behaviour.

### 19.4 What is not

- adding a new optional field;
- adding a new valid enum value;
- adding an entirely optional section;
- **moving a field from DECLARED to ENFORCED.**

The last deserves comment. Promoting a field to ENFORCED can certainly stop an
agent that a previous version let run — but the manifest declared the
constraint, and Constle's whole premise is that a declared constraint should be
real. Under this specification that is a bug fix, not a breach of compatibility.
Such promotions are always called out in the changelog.

---

## 20. Changelog

### 0.1.0 — 2026-08-16

First numbered release of this specification, and the first revision verified
field-by-field against the runtime rather than against intent.

**Added — sections that did not previously exist in this document:**

- `mcp`: gate-proxied MCP servers, tool allowlists, and the `pricing` /
  `meters` metering model (§9).
- `a2a`: signed agent-to-agent peers, the host-side listener, and the no
  discovery scope decision (§10).
- `identity.did`: `did:key` identity, signed and hash-chained audit logs, and
  the fail-closed run behaviour (§5.4).
- `spending.alerts.warn_at_pct_of_daily` (§11.6).
- `human_gates.approval_timeout_seconds` and `human_gates.notify` (§13.4,
  §13.6).
- Cross-field validation rules, collected in one table (§16).
- The enforcement-point model — why every control sits outside the sandbox
  (§2.3), and the worked consequence for filesystem gating (§13.3).

**Corrected — the previous revision described the runtime inaccurately:**

- `spending.max_per_run_usd` and `max_per_day_usd` were documented as DECLARED.
  Both are **ENFORCED**, metered at the MCP gate against priced servers, with a
  durable per-DID daily ledger. The scope limits of that metering are now
  stated explicitly (§11.1).
- `human_gates.*` were documented as DECLARED and "planned for v1.0". Gates are
  **ENFORCED** on MCP tool calls.
- `human_gates.require_approval_for` was documented as taking capability
  categories. It takes **exact MCP tool names**; the mapping contract is now
  specified (§13.2).
- `sandbox.network.egress` was documented as ENFORCED. It is **DECLARED** — no
  code path reads it, and `egress: open` does not open the network (§7.1).
- `compliance.audit_log_level` was documented as ENFORCED with a per-level
  event table. It is **DECLARED**; logging does not vary by level (§14.1).
- `compliance.frameworks` and `geo_restrictions` were documented as DECLARED;
  they are **INFORMATIONAL**.
- `capabilities` was documented as enforcement "planned for v0.5". Its actual
  role — isolation inference plus advisory gate reporting, and nothing else —
  is now stated, along with what it is *not* (§8.1).
- `sandbox.network.allowed_hosts` was documented as required under
  `egress: restricted`. It is optional; an empty list means no egress.
- References to Constle release versions (v0.4, v0.5) were removed. This
  document now describes the runtime it ships with, and states enforcement
  status directly rather than by release number.

**Structure:**

- Added spec-level version numbering, distinct from `apiVersion` (§19.1).
- Added this changelog.
- Stated the relationship between this document and the executable
  `agent-manifest.yaml` reference file, and which is normative (§1.1).

---

## 21. Roadmap — not valid manifest syntax

The following are planned but **do not exist in the runtime**. They are
described here in prose, deliberately outside the field reference, so that no
reader can mistake them for syntax that works. Nothing in this section may be
written into an Agentfile.

**`identity` — `did:web` and `did:constle` methods.**
Both require a resolution step that `did:key` does not: `did:web` fetches a
document over HTTPS, and `did:constle` implies a registry. Each therefore
introduces a trust dependency — a network path and an authority — into what is
currently a self-contained verification. That dependency has to be designed
before it ships, because a DID method whose resolution can be intercepted is
worse than no DID at all. Only `did:key` is supported today.

**`human_gates` — path- and condition-scoped approval for filesystem writes.**
Blocked on the host-side file watcher described in §13.3. The field shape is
not the hard part; the external chokepoint is.

**`spending` — monthly ledger enforcement for `max_per_month_usd`.**
The daily ledger already establishes the durable, DID-keyed, lock-protected
pattern; the monthly one is the same mechanism over a wider window.

**`sandbox` — enforcement of `network.egress` as a policy mode.**
Making `egress` a real policy mode distinct from the `allowed_hosts` allowlist,
so that `open` and `none` mean what they say (§7.1).

**`sandbox` — application of `disk_mb`.**
Currently parsed and defaulted but imposed by neither backend (§6.5).
