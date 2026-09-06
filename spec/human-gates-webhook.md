# Human Gates Webhook — External Decision Channel

**Status:** Draft
**Spec version:** 0.3.0 (adds §4.1 delivery mechanism and implements §5 canonicalization)
**Last updated:** 2026-09-04

## Changelog

- **0.3.0** (2026-09-04): Resolved the two questions 0.2.0 left open. §4.1 (new) specifies the delivery mechanism previously deferred as "out of scope for this revision": POST-once-then-poll against the same URL `human_gates.notify` already uses, with a derivable per-request decision endpoint. §5 canonicalization is now implemented (`internal/humangate.SubjectDigest`) rather than merely specified, with its two documented, deliberate deviations from strict RFC 8785 noted inline.
- **0.2.0** (2026-09-04): Replaced HMAC-SHA256 symmetric signing with Ed25519 asymmetric signatures. Introduced a dedicated webhook signing keypair, decoupled from `internal/identity`'s per-agent DIDs. Public key now declared in the Agentfile as a `did:key` string. Fail-closed behavior for a missing or malformed key made explicit.
- **0.1.0** (2026-08-28): Initial draft. HMAC-SHA256 signing (Stripe-style), subject-digest binding, signed-decision verbatim logging.

## 1. Purpose

When `human_gates.require_approval_for` names an MCP tool call that Constle intercepts, the runtime needs a way to ask an external decision-maker — a human, not another agent — whether the call should proceed. This spec defines that channel: the wire format of the request Constle sends out, the wire format of the decision that comes back, and how Constle verifies the decision actually came from the party the Agentfile designates as the approver.

It does **not** define how the approver's UI collects the decision. That's implementation-specific (Slack button, web form, CLI prompt) and out of scope.

## 2. Trust model

Constle's identity system (`internal/identity`, `pkg/did`) authenticates **agents**, not people. `identity.Create()` issues one Ed25519 keypair per agent, keyed by agent name. There is no existing concept of a human-held key, and the `Owner` field elsewhere in the Agentfile is a free-text label — it is checked against what's written, not cryptographically bound to anything.

This spec introduces a **separate keypair, scoped only to the human-gates webhook flow.** It is not an agent identity, is not created by `identity.Create()`, and is not tracked anywhere `internal/identity` looks. Reusing an agent's DID for a human approver would conflate "the agent that's boxed" with "the person approving what it does" — a fusion this spec deliberately avoids.

The webhook's public key **is** encoded as a `did:key` string, using the same multicodec/Ed25519 wire format `pkg/did` already decodes. This is a formatting-convenience decision, not a model decision: `pkg/did`'s decoder is generic to any Ed25519 public key regardless of who holds it, so reusing it here costs zero new code — but it does not imply the webhook keypair is, or becomes, an agent identity.

## 3. Agentfile field

```yaml
human_gates:
  require_approval_for:
    - "fs.write"
    - "network.request"
  approver_pubkey: "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"  # example value
```

- `approver_pubkey` is **required** whenever `require_approval_for` is non-empty. An Agentfile that declares gated tools without an `approver_pubkey` fails `constle validate`.
- Format: a `did:key` multibase string encoding a single Ed25519 public key (32 bytes), decoded via `pkg/did.Decode()`.
- Rotation is manual: changing the approver means editing this field and redeploying. There is no registry or discovery mechanism (see §9).

## 4. Request: Constle → decision endpoint

```json
{
  "request_id": "hg_7f3a9c2e",
  "agent_name": "invoice-processor",
  "tool_call": {
    "name": "fs.write",
    "arguments": { "path": "/data/out/report.csv", "content": "..." }
  },
  "subject_digest": "sha256:4b3f...e91a",
  "timestamp": "2026-09-04T14:22:03Z"
}
```

- `subject_digest` is SHA-256 over the exact, canonical byte representation of `tool_call` (§5) — this is what the approver is actually signing off on, byte for byte.
- No response within the configured timeout = denied (existing behavior, unchanged).
- Constle MAY include additional fields beyond the five above — `run_id`, `approval_timeout_seconds`, `timeout_at`, `on_timeout` — for a receiver's own bookkeeping (a countdown display, knowing when to give up holding a gate open). These carry no cryptographic weight: the signed statement in §6 is exactly `request_id + "." + decision + "." + subject_digest`, nothing else. A receiver MUST NOT require them; one that only implements the five fields above still works correctly end to end.

## 4.1 Delivery mechanism

Constle POSTs the §4 request to the URL configured via `human_gates.notify` (`channel: webhook`, `url_secret_ref`) — the same URL that already receives gate-triggered notifications; there is no separate URL to configure for decisions. The receiver acknowledges with any `2xx` status. `request_id` is the idempotency key: a receiver MUST treat a repeated POST carrying the same `request_id` as a retry of the same gate, never as a new one.

The decision is fetched by polling `GET <configured URL>/<request_id>/decision` — derivable from the configured URL and `request_id` alone, so a receiver that never saw the POST (or whose `2xx` response was lost in transit) still exposes a discoverable decision endpoint once it learns about the gate by whatever means. Poll responses:

| Response | Meaning |
|---|---|
| `200` with a decision body (§6) | Decided. Constle verifies it per §7 and stops polling either way — an invalid decision denies the call (§8); it does not fall back to continued polling. |
| anything else (`202`, `404`, `5xx`, connection failure, timeout, …) | Not yet decided. Constle retries the POST (if not yet acknowledged) and re-polls, on a fixed interval, until a decision arrives or the gate's timeout elapses. |

A receiver MAY hold the GET open before answering, as a latency optimization — Constle neither requests nor requires this; it simply polls again on its own schedule regardless.

Every outbound request is bound by the gate's own `approval_timeout_seconds` deadline, computed once when the gate opens. No single request, retry, or poll extends a decision's validity past that deadline, and no response arriving after it is honored — unchanged from the existing timeout behavior.

## 5. Canonical subject encoding

`subject_digest` must be independently reproducible on both sides, or the binding in §6 is meaningless:

1. `tool_call` serialized as JSON with sorted object keys, no whitespace (RFC 8785 JCS-style canonicalization).
2. UTF-8 encoded.
3. SHA-256 of the resulting bytes, hex-encoded, prefixed `sha256:`.

Constle computes this once when building the request. The decision endpoint doesn't have to recompute it to respond — but should, to confirm it's approving what it thinks it's approving (§6).

> **Note — this is a second canonicalization convention, not a reuse of the existing one.** The codebase's two existing signed-payload flows (`audit.Entry` in `internal/audit/logger.go`, and `a2a.Envelope` in `internal/a2a/envelope.go`) both deliberately avoid re-canonicalization: they sign/verify over the exact wire bytes produced by a single `encoding/json.Marshal` call, with the signature field declared last and stripped by byte-offset rather than by re-serializing. `envelope.go` states this explicitly as a design choice ("no re-canonicalization, so verification is over the very bytes that traveled"). RFC 8785 JCS is the opposite strategy: both sides independently re-derive canonical bytes from a parsed structure, which only holds if both implementations produce identical output (sorted keys, number formatting, escaping) for every value in `tool_call.arguments` — a guarantee `encoding/json` does not provide out of the box and Go's stdlib has no built-in JCS encoder for. This isn't a hard conflict — `tool_call` is a fresh object, not a shared struct with the other two flows — but it does mean the codebase would carry two different canonicalization philosophies for adjacent problems. Worth a deliberate call before implementation, not an accretion by default.

**Implemented as `internal/humangate.SubjectDigest`, "-style" rather than a strict RFC 8785 encoder**, on the strength of two guarantees `encoding/json` already provides: `Marshal` always emits map keys in sorted order, and decoding with `UseNumber()` carries each number's original literal text through untouched rather than the lossy `float64` default. This is deliberately not a full RFC 8785 implementation; the one documented gap is that object keys are ordered by Go's byte-wise UTF-8 comparison rather than UTF-16 code-unit order — the two agree for every key made of Basic-Multilingual-Plane characters (in practice, every real MCP tool argument name) and diverge only outside it. A future revision that needs strict cross-language byte-for-byte reproducibility should adopt a dedicated JCS library instead.

## 6. Response: decision endpoint → Constle

```json
{
  "request_id": "hg_7f3a9c2e",
  "decision": "approved",
  "subject_digest": "sha256:4b3f...e91a",
  "signature": "z3xQb...c7f1",
  "decided_at": "2026-09-04T14:22:41Z"
}
```

- `request_id`: **must echo the request's `request_id` verbatim.** It is what binds the decision to one specific gate. Two gates for the same tool call with the same arguments are indistinguishable by `subject_digest` alone, so a decision that does not echo the id is answering a different gate and is denied (§7 step 4), however genuine its signature.
- `decision`: `"approved"` or `"denied"`. Any other value, or a missing field, is treated as denied.
- `subject_digest`: **must echo the digest from the request verbatim.** The approver isn't signing "I approve request hg_7f3a9c2e" (a label Constle could relabel later); they're signing the literal hash of the tool-call bytes. What-you-see-is-what-you-sign.
- `signature`: Ed25519 signature over the exact bytes `request_id + "." + decision + "." + subject_digest` (UTF-8, ASCII period separators), signed with the private key matching the Agentfile's `approver_pubkey`.

## 7. Verification (Constle side)

1. Decode `approver_pubkey` from the Agentfile via `pkg/did.Decode()`.
2. Reconstruct the signed payload (`request_id + "." + decision + "." + subject_digest`) from the response fields.
3. Verify `signature` against that payload with the decoded public key.
4. Confirm the response's `request_id` matches the one Constle minted for this gate.
5. Confirm the response's `subject_digest` matches the one Constle sent in the request.
6. Only if steps 3, 4 **and** 5 succeed, and `decision == "approved"`, does the tool call proceed.

> **Steps 4 and 5 are separate checks, and neither is implied by step 3.** The signed payload covers `request_id` and `subject_digest` both, so a valid signature proves only that the approver said this about *that* request_id and *that* digest — not that either is the one this call is waiting on. Checking the digest alone leaves the gate open to replay: two invocations of the same tool with the same arguments share a `subject_digest` by construction (§5 is a pure function of name and arguments), and `request_id` is the only thing distinguishing them. Without step 4, a decision genuinely signed for the first invocation verifies cleanly against the second, and one human "yes" to a repeatable call silently answers every identical gate that follows it. Step 4 is checked against the locally-held id rather than inferred from the decision having been fetched from a `request_id`-derived URL (§4.1) — a verification step that fails closed cannot depend on how its input was obtained.

## 8. Fail-closed behavior

| Condition | Result |
|---|---|
| `approver_pubkey` missing from Agentfile | `constle validate` fails — agent cannot run at all |
| `approver_pubkey` present but not a valid `did:key` Ed25519 string | `constle validate` fails |
| Signature verification fails | denied, logged as `EventGateSignatureInvalid` |
| `request_id` mismatch between request and response | denied, logged as `EventGateRequestIDMismatch` |
| `subject_digest` mismatch between request and response | denied, logged as `EventGateDigestMismatch` |
| Response timeout | denied (existing behavior, unchanged) |
| `decision` missing, malformed, or anything other than `"approved"` | denied |

There is no code path that treats an unverifiable or malformed decision as approved. A broken or misconfigured webhook fails toward blocking the agent, never toward letting it through.

> **Naming note:** `internal/audit/logger.go` names its existing gate events `EventGateTriggered`, `EventGateApproved`, `EventGateDenied`, `EventGateTimeout` (string values `"gate_triggered"`, `"gate_approved"`, `"gate_denied"`, `"gate_timeout"`) — a `Gate` prefix, not `HumanGate`. The three new constants above follow that existing convention (`EventGateSignatureInvalid` / `"gate_signature_invalid"`, `EventGateRequestIDMismatch` / `"gate_request_id_mismatch"`, `EventGateDigestMismatch` / `"gate_digest_mismatch"`) rather than introducing a new `HumanGate` prefix alongside it.

## 9. Audit log

The full response object — `signature` included — is written to the audit log verbatim, alongside the original request. Anyone holding the Agentfile's `approver_pubkey` can re-verify, offline, that a given decision was genuinely signed by the approver's key over that exact tool call.

## 10. Known limitations

- **No rotation or revocation mechanism.** A compromised approver key stays valid until someone notices and edits the file.
- **The webhook keypair is not part of `internal/identity`.** A future version may unify it with the agent DID system if a real need for cross-referencing emerges.
- **Ed25519 removes host-side forgery, not host-side coercion.** The runtime host can still lie about what it's asking approval for before the digest is computed. This spec closes the "declared approval that was never real" gap; it doesn't make the host itself trustworthy by assumption.
- **Single approver per agent.** Multi-approver / M-of-N gating is not supported by this version.
