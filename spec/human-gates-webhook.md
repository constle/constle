# Constle Human-Gate Webhook Specification

**Version:** 1.0.0-draft
**Status:** Draft. Field names and semantics may change before v1.0.
**Last updated:** 2026-08-28
**Source of truth (once implemented):** `internal/mcpgate/notify.go`, `internal/mcpgate/webhook_approver.go`
**Canonical URL:** https://constle.dev/spec/human-gates-webhook
**Manifest field:** `human_gates.notify[]` (see `spec/agent-manifest.md`)

---

## Overview

When a gated tool call occurs, the Constle runtime pauses the agent and asks a human whether
the call may proceed. Today that question is asked on the operator's terminal. This document
specifies how the runtime asks the same question of an **external system** over HTTP, and how
that system answers.

The external system — the **receiver** — can be anything that speaks HTTP: a twenty-line
script on the same laptop, a chat-tool relay, an incident-management integration, an internal
dashboard, or a hosted approval service. The contract is deliberately small enough that a
receiver fits in one request handler, and deliberately strict enough that a decision cannot be
forged, replayed, or misapplied to a different action than the one the human saw.

Design goals, in priority order:

1. **A decision is only ever acted on if it is authentic, fresh, and bound to the exact action
   it was made about.** Everything else is secondary.
2. **The host originates every connection.** The sandboxed guest never touches the webhook.
   The runtime only ever connects to the one URL the operator configured — never to a URL a
   receiver, an agent, or a redirect supplied.
3. **The simplest receiver is trivial.** One URL, one HTTP method, one content type, one
   signature scheme in both directions, and a receiver that wants nothing but a notification can
   ignore everything except the first request.
4. **Proven patterns over new ones.** The signature scheme is the one Stripe and GitHub
   converged on. Polling cadence is controlled by `Retry-After`, a 1999 HTTP header. Every
   choice below cites where it comes from.

Deliberately out of scope for v1: fan-out to multiple receivers with quorum rules, receiver
discovery, event types other than gate decisions, and asymmetric (public-key) receiver
identity. Section 11 records where the design leaves room for these.

---

## 1. Terminology

| Term | Meaning |
|------|---------|
| **Host** | The Constle runtime process (`constle run`) on the operator's machine or CI runner. It is the enforcement point: it holds the gated call and decides whether to forward it. |
| **Guest** | The sandboxed agent. Has no access to the webhook URL, the signing secret, or the host's HTTP client. |
| **Receiver** | The HTTP endpoint at the configured URL. Anything that implements Section 6. |
| **Gate** | One paused tool call awaiting a decision. Identified by a `gate_id`. |
| **Decision** | An `approve` or `deny` verdict for one gate, delivered by the receiver in the format of Section 7. |
| **Subject** | The digest of the exact bytes the host will forward if the gate is approved. Section 5.3. |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 2. Manifest Configuration

The `human_gates.notify` list already exists in the AgentManifest. This spec adds one required
field (`secret_ref`) and one optional field (`name`) to each webhook entry.

```yaml
human_gates:
  enabled: true
  require_approval_for: [transfer_funds, delete_records]
  approval_timeout_seconds: 300
  on_timeout: abort
  notify:
    - channel: webhook
      name: approvals                       # optional; appears in audit log
      url_secret_ref: GATE_WEBHOOK_URL      # env var holding the URL
      secret_ref: GATE_WEBHOOK_SECRET       # env var holding the HMAC key
```

### notify[].channel

| | |
|-|-|
| Type | string |
| Required | yes |
| Valid values | `webhook` |
| Enforcement | VALIDATED |

Only `webhook` is defined. Any other value is a validation error, so a declared notification
never silently goes nowhere.

### notify[].url_secret_ref

| | |
|-|-|
| Type | string |
| Required | yes |
| Enforcement | ENFORCED — run refuses to start if the variable is unset |

Name of the environment variable holding the receiver URL. The URL itself never appears in the
manifest, the audit log, or the guest.

The URL MUST use the `https` scheme, except that `http` is permitted when the URL host is a
loopback address (`localhost`, `127.0.0.0/8`, `::1`) so that a local script can act as a
receiver without a certificate. The URL MUST NOT contain userinfo (`user:pass@`). The URL MAY
contain a path and query string; the host sends every request to exactly this URL, unchanged.

**Change from the current runtime:** an unset `url_secret_ref` variable currently produces a
warning and the gate falls back to terminal-only. Under this spec it is a startup failure. The
rationale is the same as `identity.did` failing closed: a manifest that declares external
approval must never quietly run without it.

### notify[].secret_ref

| | |
|-|-|
| Type | string |
| Required | yes |
| Enforcement | ENFORCED — run refuses to start if the variable is unset or shorter than 32 bytes |

Name of the environment variable holding the shared HMAC key used to sign every request the
host sends and every decision the receiver returns (Section 4). The key is an opaque byte
string; it is used exactly as found in the variable, with no decoding. It MUST be at least 32
bytes. Operators SHOULD generate it from a CSPRNG (`openssl rand -hex 32` yields a 64-byte
ASCII key, which is fine).

Signing is not optional. An unsigned webhook is a notification, not an approval channel, and
this spec exists for approvals. An operator who genuinely wants notify-only behaviour still sets
a secret and simply writes a receiver that never returns a decision (Section 6.4).

### notify[].name

| | |
|-|-|
| Type | string |
| Required | optional |
| Default | the entry's zero-based index, as a string |
| Enforcement | INFORMATIONAL — recorded in audit events |

Human-readable label for the receiver, written into `decided_by` and delivery-failure audit
events. Never sent to the receiver.

### Multiple entries

`notify` is a list. Each entry is an independent receiver with its own URL and secret. Every
receiver is notified of every gate; the **first valid decision from any source** — any receiver
or the terminal — closes the gate. There is no quorum in v1 (Section 11).

---

## 3. Transport Rules

These rules apply to every HTTP request the host makes under this spec.

| Rule | Value | Why |
|------|-------|-----|
| Method | `POST`, always | One method means one signing rule (over the body) and one receiver handler. Polling with `GET` would need a separate scheme for signing query strings. |
| `Content-Type` | `application/json; charset=utf-8` | |
| `User-Agent` | `constle/<version>` | Lets receivers log and rate-limit by client. |
| Redirects | **Never followed.** A 3xx response is a delivery failure. | The host connects only to the URL the operator configured. Following a redirect would let a receiver — or anyone who can answer for it — move host traffic to an arbitrary destination. Same principle as `allowed_hosts`. |
| TLS | System trust store; certificate verification MUST NOT be disabled. | |
| Connect timeout | 10 s | |
| Total request timeout | `hold_seconds + 10 s` (Section 5.2) | Permits long-hold responses without hanging forever. |
| Response body cap | 64 KiB. Larger bodies are a delivery failure. | Bounds memory held per gate. A decision is a few hundred bytes. |
| Origin | The **host** process only. | The guest has no route to this URL, no copy of the secret, and no way to trigger these requests except by making a gated tool call. |

Note on `allowed_hosts`: the receiver URL is a host-side destination, not guest egress. It is
**not** subject to, and does not need to appear in, `sandbox.network.allowed_hosts`.

---

## 4. Request Signing

Every request body the host sends carries a signature header; every decision body the receiver
returns carries the same header. The scheme is identical in both directions so a receiver
implements it once.

### 4.1 Header format

```
Constle-Signature: t=1787918400,v1=d8c1a924…e21df0
```

A comma-separated list of `key=value` pairs:

| Key | Value |
|-----|-------|
| `t` | Unix timestamp (integer seconds, UTC) at which the signer produced the signature. |
| `v1` | Lower-case hex HMAC-SHA256, computed as in 4.2. |

A verifier MUST ignore keys it does not recognise, and MUST accept more than one `v1` pair
(checking each and succeeding if any matches). This is what allows a secret to be rotated: the
signer signs with both the old and the new secret for a transition window, then drops the old.

### 4.2 Signed string

```
signed_string = <t> "." <raw request/response body bytes>
v1            = hex( HMAC-SHA256( key = secret, message = signed_string ) )
```

The body is signed **as bytes on the wire**, not as re-serialized JSON. Verifiers MUST compute
the HMAC over the raw body before any JSON parsing. This is the single most common
webhook-verification bug in the wild (parse, re-stringify, sign the wrong bytes), so it is worth
stating explicitly.

### 4.3 Verification

A verifier MUST:

1. Parse the header. Reject if `t` or at least one `v1` is missing.
2. Reject if `|now − t| > 300 s` (five minutes). This bounds the replay window.
3. Compute the expected HMAC over `t "." body` with each secret currently accepted.
4. Compare with each supplied `v1` using a **constant-time** comparison.
5. Accept if any comparison succeeds.

Steps 2 and 4 are not optional. Without step 2, a captured request is valid forever; without
step 4, a network-adjacent attacker can recover the MAC byte-by-byte.

### 4.4 Where this comes from

This is Stripe's `Stripe-Signature` scheme (`t=…,v1=…`, HMAC-SHA256 over `t.payload`, five-minute
tolerance, multiple `v1` for rotation), which is the most widely re-implemented webhook signature
format in existence and has library support in every mainstream language.

GitHub's `X-Hub-Signature-256` is the other mature reference. It uses the same primitive
(HMAC-SHA256 over the raw body) but **omits the timestamp**, relying on the receiver to
deduplicate by delivery ID. For a notification that is acceptable; for an *approval* — where a
replayed "approve" is the attack — the timestamp is what makes step 2 possible, so Stripe's
variant is the right one to borrow. The delivery ID (Section 5.1) is retained from GitHub's
design for idempotency.

HMAC-SHA256 with a shared secret rather than a public-key signature: a shared secret is
symmetric, so it cannot prove to a *third party* which side produced a message. For host ↔
receiver authentication that limitation is irrelevant — each side is verifying the other — and
the operational simplicity (one string in two env vars, no key distribution, no
canonicalization) is decisive for a primitive that must be trivially implementable. Section 11
notes the asymmetric upgrade path.

### 4.5 Test vector

Secret (ASCII, 32 bytes): `0123456789abcdef0123456789abcdef`

Request body (exact bytes, no trailing newline):

```json
{"spec_version":1,"event":"gate.opened","delivery_id":"4b0e7f9a-3c1d-4e6b-9a2f-8d5c1e7b3a90","gate_id":"gate_01K3P2Q8ZV4M6X9R7T5W3Y1N0B","run_id":"run_20260828T120000Z_7f3a","agent":{"name":"payments-agent","owner":"alice@example.com"},"action":{"kind":"mcp_tool_call","server":"bank","tool":"transfer_funds","arguments":{"to":"acct_9f3","amount_cents":125000}},"subject":"sha256:82ddb5c93ec29d332e8041b39e9338252c7e21eb3c3731465404e9b332278d67","opened_at":"2026-08-28T12:00:00Z","expires_at":"2026-08-28T12:05:00Z","on_expiry":"abort","hold_seconds":25}
```

`t = 1787918400` (2026-08-28T12:00:00Z)

```
Constle-Signature: t=1787918400,v1=d8c1a9243e9e902a018d9a414f12336d4e55148822142af699fd0bf922e21df0
```

Decision body (exact bytes):

```json
{"gate_id":"gate_01K3P2Q8ZV4M6X9R7T5W3Y1N0B","decision":"approve","subject":"sha256:82ddb5c93ec29d332e8041b39e9338252c7e21eb3c3731465404e9b332278d67","decided_by":"alice@example.com","reason":"vendor invoice #4471","decided_at":"2026-08-28T12:00:42Z"}
```

`t = 1787918442`

```
Constle-Signature: t=1787918442,v1=db49276ffc5b569b1b041d3d125bbe452064c8dbde12d95bbb2917d5524bb293
```

The `subject` above is `sha256` of the exact bytes `{"to":"acct_9f3","amount_cents":125000}`.
These vectors were produced with `openssl dgst -sha256 -hmac` and `sha256sum`; the
implementation's test suite MUST reproduce them.

---

## 5. Events the Host Sends

All events share an envelope. All timestamps are RFC 3339 in UTC with a `Z` suffix.

```json
{
  "spec_version": 1,
  "event": "gate.opened" | "gate.poll" | "gate.closed",
  "delivery_id": "<uuid>",
  "gate_id": "<string>",
  "run_id": "<string>",
  ...event-specific fields
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `spec_version` | integer | Always `1` for this document. Receivers MUST reject events whose `spec_version` they do not implement. |
| `event` | string | Event type. Receivers MUST ignore event types they do not recognise (respond `202`), so new event types can be added without a major version. |
| `delivery_id` | string | UUIDv4, unique per logical delivery. **Retries of the same delivery reuse the same `delivery_id`**, so a receiver that stores it can deduplicate. (Pattern: GitHub `X-GitHub-Delivery`.) |
| `gate_id` | string | Identifies the gate. `gate_` followed by 26 Crockford-base32 characters (a ULID: time-ordered, 80 random bits). Generated by the host, never derived from guest-controlled input. |
| `run_id` | string | The Constle run, as it appears in the audit log. |

### 5.1 `gate.opened`

Sent once when a gate triggers. This is the notification, and it carries everything a human
needs to decide.

```json
{
  "spec_version": 1,
  "event": "gate.opened",
  "delivery_id": "4b0e7f9a-3c1d-4e6b-9a2f-8d5c1e7b3a90",
  "gate_id": "gate_01K3P2Q8ZV4M6X9R7T5W3Y1N0B",
  "run_id": "run_20260828T120000Z_7f3a",
  "agent": {
    "name": "payments-agent",
    "owner": "alice@example.com",
    "did": "did:key:z6Mk…"
  },
  "action": {
    "kind": "mcp_tool_call",
    "server": "bank",
    "tool": "transfer_funds",
    "arguments": {"to": "acct_9f3", "amount_cents": 125000},
    "arguments_truncated": false
  },
  "subject": "sha256:82ddb5c9…278d67",
  "opened_at": "2026-08-28T12:00:00Z",
  "expires_at": "2026-08-28T12:05:00Z",
  "on_expiry": "abort",
  "hold_seconds": 25
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `agent.name` | string | `identity.name` from the manifest. |
| `agent.owner` | string | `identity.owner`, or `"unknown"` — identical to the audit log. |
| `agent.did` | string, optional | `identity.did` when the agent has one. Lets a receiver correlate with signed audit logs. |
| `action.kind` | string | `mcp_tool_call` is the only kind in v1. The field exists so that gates on other action types (a network egress gate, a spend threshold) can reuse this contract. |
| `action.server`, `action.tool` | string | The MCP server ID and tool name exactly as the gate proxy observed them. |
| `action.arguments` | any JSON | The tool call's `params.arguments`, embedded verbatim. If the raw arguments exceed 64 KiB the host embeds `null` and sets `arguments_truncated: true`; the `subject` still covers the full bytes. |
| `subject` | string | Digest of the action, Section 5.3. |
| `opened_at` | timestamp | When the gate triggered. |
| `expires_at` | timestamp | `opened_at + approval_timeout_seconds`. After this instant the host applies `on_expiry` and ignores any decision. |
| `on_expiry` | string | `abort` or `proceed` — the manifest's `on_timeout`. Sent so a receiver can render the stakes of not answering. |
| `hold_seconds` | integer | How long the receiver MAY hold this request open before answering (Section 6.3). Fixed at 25 in v1. |

Everything a receiver needs to render the request and decide is in this one message; a receiver
never has to call back to the host for more.

### 5.2 `gate.poll`

Sent repeatedly after a `gate.opened` that was acknowledged but not decided (Section 6.2), until
a decision arrives or the gate expires.

```json
{
  "spec_version": 1,
  "event": "gate.poll",
  "delivery_id": "…",
  "gate_id": "gate_01K3P2Q8ZV4M6X9R7T5W3Y1N0B",
  "run_id": "run_20260828T120000Z_7f3a",
  "subject": "sha256:82ddb5c9…278d67",
  "expires_at": "2026-08-28T12:05:00Z",
  "hold_seconds": 25
}
```

The poll deliberately repeats `subject` and `expires_at` so a receiver that lost its state
(restarted) can still answer coherently or at least recognise that it cannot.

Cadence: the host waits `Retry-After` seconds from the previous response if present (clamped to
1–60), otherwise 5 seconds, then sends the next poll. Each poll is a fresh `delivery_id`.

Why the host polls rather than the receiver calling back: the host is very often a laptop, a CI
runner, or a machine behind NAT with no inbound route. Requiring it to expose an endpoint would
exclude the most common deployment. Why poll the *same* URL rather than a receiver-supplied
status URL: Section 3 — the host never connects anywhere the operator did not configure.

### 5.3 `subject` — binding a decision to bytes

```
subject = "sha256:" + hex( SHA-256( raw params.arguments bytes as received from the guest ) )
```

The subject is computed over the exact bytes the host holds and will forward upstream if the
gate is approved. It is not a canonicalized or re-serialized form. A receiver can recompute it
from `action.arguments` only if those were embedded untruncated *and* the guest emitted compact
JSON; the receiver is not expected to recompute it. Its job is different: a decision MUST echo
the subject, and the host MUST refuse any decision whose subject does not match the gate's.

What this buys, concretely:

- A decision cannot be applied to a different gate that reused an ID by accident (host restart,
  receiver bug, copy-paste in a dashboard) — it is bound to the content, not just the label.
- A human-facing receiver can display the subject prefix next to the arguments it renders. If
  the receiver's own rendering pipeline is compromised or buggy and shows different arguments
  than the host holds, the host still only executes what the human's echoed subject matches.
  This is the "what you see is what you sign" property from document-signing, applied to a
  tool call.
- In the audit log (Section 9), the recorded decision is self-describing: `gate_approved` with
  a signed decision containing subject `S` is evidence that the secret holder approved the
  action whose arguments hash to `S`, independent of the host's own summary of the event.

### 5.4 `gate.closed`

Sent once, best-effort, after the gate reaches a terminal state, so that receivers can update a
card, close an incident, or stop a timer. Never retried beyond one attempt; its failure is logged
but does not affect the run.

```json
{
  "spec_version": 1,
  "event": "gate.closed",
  "delivery_id": "…",
  "gate_id": "gate_01K3P2Q8ZV4M6X9R7T5W3Y1N0B",
  "run_id": "run_20260828T120000Z_7f3a",
  "outcome": "approved" | "denied" | "expired",
  "decided_by": "terminal" | "webhook:<name>" | null,
  "closed_at": "2026-08-28T12:00:42Z"
}
```

A receiver MUST tolerate receiving `gate.closed` for a gate it decided itself, for a gate
another receiver or the terminal decided, and for a gate it has never heard of.

---

## 6. Receiver Responses

The receiver answers each event with an HTTP status that tells the host what to do next. There
are exactly three meaningful classes.

### 6.1 `200 OK` with a decision body — decided

The gate is decided. The body MUST be a decision (Section 7) and MUST carry a valid
`Constle-Signature` header. The host validates it (Section 7.2); an invalid decision is treated
as a delivery failure, not as a deny, and is logged as `gate_decision_rejected`.

A `200` with an empty or non-decision body is a protocol error and is treated as a delivery
failure.

### 6.2 `202 Accepted` — pending

The receiver has the event and has no decision yet. The host will poll (5.2). The body is
ignored. The receiver MAY set `Retry-After` to control polling cadence. This is the ordinary
response to `gate.opened` for any receiver that hands off to a human.

For `gate.closed`, `202` (or `200`) simply acknowledges.

### 6.3 Holding the request — long-poll

A receiver MAY hold *any* request open for up to `hold_seconds` before responding, and then
respond `200` + decision if one arrived during the hold, or `202` if not. This lets a
synchronous receiver — a script that waits for a keypress, a service that awaits an in-memory
channel — deliver a decision with sub-second latency without any polling round-trip. The host's
request timeout is `hold_seconds + 10`.

A receiver that neither holds nor polls is fine too; it just costs one poll interval of latency.

### 6.4 Anything else — delivery failure

| Response | Host behaviour |
|----------|----------------|
| Network error, timeout, TLS failure, 3xx, `408`, `429`, any `5xx` | Retry the same delivery (same `delivery_id`) with backoff 1 s, 2 s, 4 s — at most three retries — then give up on that delivery. For `gate.poll`, give up immediately; the next poll tick is the retry. |
| Any other `4xx` | Do not retry that delivery. Log `gate_notify_failed`. |
| `200` with invalid decision | Do not retry. Log `gate_decision_rejected`. Continue polling. |

A delivery failure **never** decides a gate. The gate stays open; the terminal approver still
works; when `expires_at` passes, `on_expiry` applies. The webhook can add ways to approve; it can
never remove the timeout as the backstop.

A **notify-only receiver** — one that only wants to know gates are happening — returns `202` to
everything and never sends a decision. It gets `gate.opened`, a poll every 5 s until the gate
resolves (it may reply `Retry-After: 60` to make those rare), and `gate.closed`.

### 6.5 Receiver obligations

A receiver MUST verify `Constle-Signature` on every request before acting on it (Section 4.3).
A receiver MUST NOT act on a request whose signature fails; it SHOULD respond `401`.

A receiver SHOULD deduplicate by `delivery_id` for `gate.opened`, since retries reuse it.

A receiver MUST be prepared for `gate.poll` after it has already returned a decision — the host
may not have received the response — and SHOULD return the same decision again. The host
ignores decisions for gates it has already closed.

---

## 7. The Decision

### 7.1 Body

```json
{
  "gate_id": "gate_01K3P2Q8ZV4M6X9R7T5W3Y1N0B",
  "decision": "approve",
  "subject": "sha256:82ddb5c9…278d67",
  "decided_by": "alice@example.com",
  "reason": "vendor invoice #4471",
  "decided_at": "2026-08-28T12:00:42Z"
}
```

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `gate_id` | string | yes | MUST equal the gate being answered. |
| `decision` | string | yes | `approve` or `deny`. Nothing else. There is no "defer" — pending is expressed by `202`, not by a decision. |
| `subject` | string | yes | MUST equal the gate's subject (5.3). |
| `decided_by` | string | yes | Free-form identifier of the deciding principal (an email, a chat user ID, `"policy:auto-approve-under-100"`). Written verbatim to the audit log. The host does not verify it — authenticity comes from the signature, attribution comes from the receiver. |
| `reason` | string | optional | Free-form, ≤ 1 KiB, audit log only. |
| `decided_at` | timestamp | optional | When the human acted; informational. Freshness is judged by the signature's `t`, not this field. |

Five required fields, two of which are echoes. That is the minimum for a decision that is
unambiguous (`gate_id`), bound (`subject`), meaningful (`decision`), and attributable
(`decided_by`).

### 7.2 Host validation

The host applies a decision only if **all** of the following hold; otherwise it discards the
response and logs `gate_decision_rejected` with the failing check:

1. The HTTP status is `200`.
2. `Constle-Signature` is present and verifies (Section 4.3) with the secret of the receiver
   that was called — a decision signed with receiver A's secret arriving on receiver B's URL is
   rejected.
3. `gate_id` matches a gate that is currently open in this host process.
4. `subject` matches that gate's subject.
5. `decision` is exactly `approve` or `deny`.
6. `decided_by` is a non-empty string.
7. The current time is before the gate's `expires_at`.

The first decision passing all checks closes the gate. Subsequent decisions for the same gate,
from any source, are ignored and logged at debug level. A gate is decided at most once, ever.

### 7.3 Interaction with the terminal approver

The terminal prompt and the webhook run concurrently on the same gate. Whichever produces a
valid decision first wins; the other is cancelled. A terminal `y` and a webhook `deny` racing is
resolved by arrival order at the gate, and the audit log records which one won. This mirrors how
the runtime treats every other approval source — there is one gate with one outcome, and the
sources are just inputs.

---

## 8. Sequence

```
guest ──tools/call──▶ host gate ──────────────────────────────────────────────▶ upstream MCP
                       │  (paused)                                               ▲
                       │                                                         │
                       ├─ POST gate.opened ─────▶ receiver                       │
                       │      ◀── 202 (+Retry-After) ─┤                          │
                       │                              │  human decides           │
                       ├─ POST gate.poll ───────────▶ │                          │
                       │      ◀── 202 ────────────────┤                          │
                       ├─ POST gate.poll ───────────▶ │                          │
                       │      ◀── 200 + signed decision                          │
                       │  verify sig, gate_id, subject, expiry                    │
                       │  audit: gate_approved {decided_by: "webhook:approvals"}  │
                       ├─ POST gate.closed ─────────▶ receiver                    │
                       └── forward ──────────────────────────────────────────────┘
```

The synchronous variant collapses the middle: the receiver holds `gate.opened` for up to 25 s
and answers `200` + decision directly.

---

## 9. Audit Log

This spec adds to, and never changes the meaning of, the existing gate events. All entries go
through the single audit logger and are therefore signed and hash-chained whenever the agent has
an identity (`spec/identity.md`).

| Event | When | Fields added by this spec |
|-------|------|---------------------------|
| `gate_triggered` | unchanged | `gate_id`, `subject` |
| `gate_notified` | each successful (2xx) delivery of `gate.opened` | `gate_id`, `receiver` (the `name`), `delivery_id`, `attempt` |
| `gate_notify_failed` | a delivery gave up (6.4) | `gate_id`, `receiver`, `delivery_id`, `event`, `status` or `error` |
| `gate_decision_rejected` | a `200` response failed 7.2 | `gate_id`, `receiver`, `check` (which of 7.2 failed) |
| `gate_approved` / `gate_denied` | unchanged | `gate_id`, `decided_by` becomes `"terminal"` or `"webhook:<name>"`; when webhook: `decision` = the **raw decision body and its `Constle-Signature` header, verbatim** |
| `gate_timeout` | unchanged | `gate_id` |

Recording the decision verbatim, with its signature, is the point of the whole design from an
audit standpoint. The log line for an approval then contains not merely the host's claim
"approved by webhook", but the signed artifact itself — verifiable later by anyone holding the
receiver secret, bound to the subject digest of the arguments that were executed, inside a
hash-chained, agent-signed log. The receiver URL and the secret are never written to the log.

---

## 10. Security Considerations

**Threat: forged approval.** An attacker who can reach the host's network path (or a
misconfigured proxy that answers for the receiver) sends `200 {"decision":"approve"}`. Defeated
by the response signature (7.2 #2): without the secret the response does not verify. TLS
provides this too for the honest case; the signature provides it when TLS trust is weakened
(corporate MITM proxies, `http://localhost` receivers, a receiver whose framework strips headers
onto a different backend).

**Threat: replayed approval.** A previously valid decision is re-sent. Defeated three ways: the
signature timestamp tolerance (4.3 #2), the gate-open check (7.2 #3 — a gate is decided once),
and the subject binding (7.2 #4 — a replay against a new gate with the same `gate_id` is
impossible because IDs are 80 random bits, and against a new gate with different arguments fails
the subject).

**Threat: guest-originated approval.** The agent tries to approve itself. The guest has no
route to the receiver (not in `allowed_hosts`; the webhook is a host-side connection), no copy of
the secret (it is read from the host's environment and never enters the sandbox), and no
inbound path into the gate other than `tools/call`. An agent that discovers the receiver URL
via prompt injection still cannot produce a signature.

**Threat: guest-influenced payload.** `action.arguments` is guest-controlled and embedded
verbatim. A receiver MUST treat it as untrusted data — never render it as HTML/Markdown without
escaping, never pass it to a shell, never let it override envelope fields. The envelope fields
themselves (`gate_id`, `agent.*`, `subject`, timestamps) are host-generated and not influenced
by the guest. Prompt-injection content in `arguments` aimed at the *human approver* is precisely
what the gate exists to surface, so the receiver should show it, escaped, not hide it.

**Threat: SSRF / traffic redirection.** A receiver responds `302 Location: http://169.254.169.254/…`
or includes a "status URL" hoping the host follows it. Defeated by Section 3: no redirects, no
receiver-supplied URLs, ever. The only destination the host contacts is the configured URL.

**Threat: secret leakage.** The secret and URL live in environment variables of the host
process. They are never written to the manifest, the audit log, terminal output, or the sandbox.
`constle validate` MUST NOT print them. Operators SHOULD use a per-agent secret so that
compromising one receiver does not let it approve for other agents.

**Threat: receiver compromise.** A compromised receiver can approve anything for the agents
whose secrets it holds. This is inherent — the receiver *is* the approval authority the operator
chose. Mitigations are operational: per-agent secrets, short `approval_timeout_seconds`, and
the audit log's verbatim decision record, which makes the compromise reconstructible after the
fact. The subject binding limits the damage of a *partially* compromised receiver (e.g. a
tampered rendering layer in front of an honest signing service) to nothing: it can only approve
what the signer signed.

**Threat: denial of approval.** An attacker who can block the host → receiver path can prevent
approvals. Outcome: the gate expires and `on_expiry` applies. With `abort` (the default and the
recommended value) this is a safe failure. This is why the spec cannot and does not offer any
mode in which webhook failure results in `proceed`.

**Non-goal: receiver identity to third parties.** Because HMAC is symmetric, a recorded decision
proves "someone holding the secret" signed it, and the host itself holds the secret. A verifier
who distrusts the host operator cannot distinguish a host-forged decision from a real one.
Section 11 covers the upgrade.

---

## 11. Extension Points and Future Work

- **`action.kind`** — new gate sources (network egress approval, spend threshold approval) add a
  kind and a kind-specific object under `action`; the envelope, signing, and decision contract
  are unchanged.
- **New event types** — receivers ignore unknown events with `202`, so `gate.reminder`, or a
  `run.finished` summary, can be added in a minor version.
- **Asymmetric decisions** — an optional `decision_public_key_ref` on the notify entry would let
  a receiver sign decisions with Ed25519 (`Constle-Signature: t=…,ed25519=…`) so that the audit
  record becomes third-party-verifiable evidence the host could not have forged. The header
  format already accommodates a new key. Deferred because it moves the receiver from "two env
  vars" to "key management", which is the wrong default for v1.
- **Quorum** — `human_gates.notify.require: 2` or per-receiver `role`. The single-decision rule
  in 7.2 becomes "N distinct valid approvals". Deferred: no evidence yet of demand, and it
  complicates the interaction with the terminal approver.
- **Configurable `hold_seconds` and poll cadence** — host-side knobs deferred; the receiver
  already steers cadence with `Retry-After`.

---

## 12. Minimal Receiver

A complete, conforming receiver that lets a human approve from the shell. Shown to demonstrate
the size of the contract, not as production code.

```python
# python3 receiver.py  —  GATE_WEBHOOK_SECRET must match the host's secret_ref
import hmac, hashlib, json, os, sys, time, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ["GATE_WEBHOOK_SECRET"].encode()
decisions = {}                      # gate_id -> (body_bytes, header)
lock = threading.Lock()

def sign(body: bytes) -> str:
    t = str(int(time.time()))
    mac = hmac.new(SECRET, f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={t},v1={mac}"

def verify(header: str, body: bytes) -> bool:
    kv = dict(p.split("=", 1) for p in header.split(","))
    if abs(time.time() - int(kv["t"])) > 300:
        return False
    want = hmac.new(SECRET, f"{kv['t']}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, kv.get("v1", ""))

def ask(ev):
    a = ev["action"]
    print(f"\n[{ev['gate_id']}] {ev['agent']['name']} wants {a['server']}/{a['tool']}")
    print("  args:", json.dumps(a["arguments"])[:500])
    print("  subject:", ev["subject"][:23], " expires:", ev["expires_at"])
    ans = input("  approve? [y/N] ").strip().lower()
    body = json.dumps({
        "gate_id": ev["gate_id"],
        "decision": "approve" if ans == "y" else "deny",
        "subject": ev["subject"],
        "decided_by": os.environ.get("USER", "shell"),
    }, separators=(",", ":")).encode()
    with lock:
        decisions[ev["gate_id"]] = (body, sign(body))

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if not verify(self.headers.get("Constle-Signature", "t=0"), body):
            self.send_response(401); self.end_headers(); return
        ev = json.loads(body)
        if ev["event"] == "gate.opened":
            threading.Thread(target=ask, args=(ev,), daemon=True).start()
        with lock:
            d = decisions.get(ev["gate_id"])
        if d and ev["event"] in ("gate.opened", "gate.poll"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Constle-Signature", d[1])
            self.end_headers(); self.wfile.write(d[0])
        else:
            self.send_response(202); self.send_header("Retry-After", "2"); self.end_headers()

HTTPServer(("127.0.0.1", 8787), H).serve_forever()
```

With `GATE_WEBHOOK_URL=http://127.0.0.1:8787/` this is a working approval channel. A chat-tool
relay is the same shape: `ask()` posts a message with buttons, and the button callback fills
`decisions`.

---

## Appendix A: Field Summary

Host → receiver headers: `Content-Type`, `User-Agent`, `Constle-Signature`.
Receiver → host headers: `Constle-Signature` (on `200` only), `Retry-After` (optional, on `202`).

Events: `gate.opened`, `gate.poll`, `gate.closed`.
Statuses: `200` decided · `202` pending · other = failure.
Decision: `gate_id`, `decision`, `subject`, `decided_by`, [`reason`], [`decided_at`].

## Appendix B: Relationship to `spec/agent-manifest.md`

The `human_gates` section of the manifest spec should, when this document is adopted:

- change `notify[].url_secret_ref` from "warn if unset" to ENFORCED fail-closed;
- add `notify[].secret_ref` (required) and `notify[].name` (optional);
- link here from `human_gates.notify` and from the `identity.did` paragraph that already cites
  `url_secret_ref` as the indirection precedent.
