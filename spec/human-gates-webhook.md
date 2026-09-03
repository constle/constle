# Human Gates Webhook — External Decision Channel

**Status:** Draft
**Spec version:** 0.2.0 (supersedes 0.1.0 — HMAC design)
**Last updated:** 2026-09-04

## Changelog

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
- Delivery URL/transport is unchanged from the prior draft and out of scope for this revision.
- No response within the configured timeout = denied (existing behavior, unchanged).

## 5. Canonical subject encoding

`subject_digest` must be independently reproducible on both sides, or the binding in §6 is meaningless:

1. `tool_call` serialized as JSON with sorted object keys, no whitespace (RFC 8785 JCS-style canonicalization).
2. UTF-8 encoded.
3. SHA-256 of the resulting bytes, hex-encoded, prefixed `sha256:`.

Constle computes this once when building the request. The decision endpoint doesn't have to recompute it to respond — but should, to confirm it's approving what it thinks it's approving (§6).

> **Note — this is a second canonicalization convention, not a reuse of the existing one.** The codebase's two existing signed-payload flows (`audit.Entry` in `internal/audit/logger.go`, and `a2a.Envelope` in `internal/a2a/envelope.go`) both deliberately avoid re-canonicalization: they sign/verify over the exact wire bytes produced by a single `encoding/json.Marshal` call, with the signature field declared last and stripped by byte-offset rather than by re-serializing. `envelope.go` states this explicitly as a design choice ("no re-canonicalization, so verification is over the very bytes that traveled"). RFC 8785 JCS is the opposite strategy: both sides independently re-derive canonical bytes from a parsed structure, which only holds if both implementations produce identical output (sorted keys, number formatting, escaping) for every value in `tool_call.arguments` — a guarantee `encoding/json` does not provide out of the box and Go's stdlib has no built-in JCS encoder for. This isn't a hard conflict — `tool_call` is a fresh object, not a shared struct with the other two flows — but it does mean the codebase would carry two different canonicalization philosophies for adjacent problems. Worth a deliberate call before implementation, not an accretion by default.

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

- `decision`: `"approved"` or `"denied"`. Any other value, or a missing field, is treated as denied.
- `subject_digest`: **must echo the digest from the request verbatim.** The approver isn't signing "I approve request hg_7f3a9c2e" (a label Constle could relabel later); they're signing the literal hash of the tool-call bytes. What-you-see-is-what-you-sign.
- `signature`: Ed25519 signature over the exact bytes `request_id + "." + decision + "." + subject_digest` (UTF-8, ASCII period separators), signed with the private key matching the Agentfile's `approver_pubkey`.

## 7. Verification (Constle side)

1. Decode `approver_pubkey` from the Agentfile via `pkg/did.Decode()`.
2. Reconstruct the signed payload (`request_id + "." + decision + "." + subject_digest`) from the response fields.
3. Verify `signature` against that payload with the decoded public key.
4. Confirm the response's `subject_digest` matches the one Constle sent in the request.
5. Only if steps 3 **and** 4 succeed, and `decision == "approved"`, does the tool call proceed.

## 8. Fail-closed behavior

| Condition | Result |
|---|---|
| `approver_pubkey` missing from Agentfile | `constle validate` fails — agent cannot run at all |
| `approver_pubkey` present but not a valid `did:key` Ed25519 string | `constle validate` fails |
| Signature verification fails | denied, logged as `EventGateSignatureInvalid` |
| `subject_digest` mismatch between request and response | denied, logged as `EventGateDigestMismatch` |
| Response timeout | denied (existing behavior, unchanged) |
| `decision` missing, malformed, or anything other than `"approved"` | denied |

There is no code path that treats an unverifiable or malformed decision as approved. A broken or misconfigured webhook fails toward blocking the agent, never toward letting it through.

> **Naming note:** `internal/audit/logger.go` names its existing gate events `EventGateTriggered`, `EventGateApproved`, `EventGateDenied`, `EventGateTimeout` (string values `"gate_triggered"`, `"gate_approved"`, `"gate_denied"`, `"gate_timeout"`) — a `Gate` prefix, not `HumanGate`. The two new constants above follow that existing convention (`EventGateSignatureInvalid` / `"gate_signature_invalid"`, `EventGateDigestMismatch` / `"gate_digest_mismatch"`) rather than introducing a new `HumanGate` prefix alongside it.

## 9. Audit log

The full response object — `signature` included — is written to the audit log verbatim, alongside the original request. Anyone holding the Agentfile's `approver_pubkey` can re-verify, offline, that a given decision was genuinely signed by the approver's key over that exact tool call.

## 10. Known limitations

- **No rotation or revocation mechanism.** A compromised approver key stays valid until someone notices and edits the file.
- **The webhook keypair is not part of `internal/identity`.** A future version may unify it with the agent DID system if a real need for cross-referencing emerges.
- **Ed25519 removes host-side forgery, not host-side coercion.** The runtime host can still lie about what it's asking approval for before the digest is computed. This spec closes the "declared approval that was never real" gap; it doesn't make the host itself trustworthy by assumption.
- **Single approver per agent.** Multi-approver / M-of-N gating is not supported by this version.
