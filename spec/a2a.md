# A2A — Signed Agent-to-Agent Communication

Status: Phases 1–2 implemented (outbound + inbound listener/inbox).
Phases 3–4 (audit completion, adversarial verification) follow this design.

## Scope

A2A connects agents that are **explicitly declared as peers** in each
other's Agentfiles: a peer is a `name` + `did` + `endpoint` triple, exchanged
out of band by the operator. There is deliberately **no discovery
mechanism** anywhere in this codebase — an agent cannot find, resolve, or be
introduced to a peer it was not already configured to know about. That is a
scope decision, not a gap.

## Trust model

The project's existing trust model, applied in both directions: **the host
constle process is the trusted party; the sandbox is not.**

- The agent's Ed25519 private key lives on the host
  (`~/.constle/identities/<name>/`, mode 0600) and never enters the sandbox.
  Therefore the HOST signs every outbound call and verifies every inbound
  one. The sandbox does no cryptography at all.
- The sandbox never sees a peer's real endpoint (mirror of the MCP gate
  rule: real MCP URLs never enter the sandbox).
- The sandbox never receives raw, unauthenticated bytes from the network.
  Verification and peer authorization happen in the host process strictly
  before anything is relayed inward.

## Architecture

```
Agent A (sandbox)      A's host process              B's host process         Agent B (sandbox)
────────────────       ────────────────              ────────────────         ────────────────
POST $CONSTLE_A2A_URL
  /send/peer-b   ───▶  A2A gate:
                       sign envelope with
                       A's identity       ──POST──▶  public listener (a2a.listen):
                                                     1. cap body size, parse
                                                     2. verify signature (pkg/did)
                                                     3. sender DID ∈ declared peers?
                                                     4. addressed to B?
                                                     ── only then ──
                                                     park in inbox        ◀── GET /inbox (long-poll,
                                                     verified plaintext + ──▶     agent-initiated)
                                                     sender metadata
                                                                          ◀── POST /reply/{msg_id}
                       verify response:   ◀─signed── sign response with
                       signed by peer's       resp   B's identity
                       declared DID,
                       addressed to A,
                       bound to request
◀── response body ──── (in_reply_to)
```

### Outbound (implemented, Phase 1)

The sandbox POSTs a JSON body to `$CONSTLE_A2A_URL/send/<peer-name>`. The
gate (`internal/a2a`) signs it into an envelope with the agent's identity,
POSTs it to the declared peer's `endpoint` + `/a2a/v1/call`, verifies the
signed response (signature via the peer's declared DID, correct recipient,
`in_reply_to` bound to the request's `msg_id`), and returns only the
verified response body to the sandbox, with the verified sender in the
`X-Constle-A2A-From` header.

An undeclared peer name is rejected at the gate (403). Nothing in the
sandbox can name an endpoint — only declared peer aliases.

### Inbound (Phase 2): pull, not push

The receiving host process runs a public listener on `a2a.listen` — the
project's first host-facing listener, and therefore categorically new
attack surface. A crash or hang here takes down the host supervisor, not a
disposable sandbox, so the listener is hardened independently of — and
strictly before — any signature work:

1. exact route match (`POST /a2a/v1/call` only; everything else a flat 404);
2. hard server timeouts (header read, body read, write) and a header-size
   cap, so a slow or stalling client cannot pin connections;
3. body-size cap enforced on byte count **before any parsing**;
4. malformed input (bad JSON, framing, base64, DID) rejected via error
   returns — no panics, no body echo;
5. bounded inbox: beyond capacity the listener sheds load (503) instead of
   growing host memory.

Verification then runs in a fixed order — envelope signature (`Open`),
sender ∈ declared peers, correct recipient, replay — and each rejection is
audited with its precise failing check.

Delivery into the sandbox is **pull-based**: verified calls are parked in a
per-run inbox that the agent drains over a connection it initiates to the
gate (`GET /inbox` long-poll, then `POST /reply/{msg_id}`). This reuses the
one sandbox→host route that already exists for the MCP gate on both
backends. Push (the host dialing into the sandbox) was rejected because it
would break Docker Desktop parity (no host→container route on internal
networks) and would open the project's first inbound network hole into a
sandbox.

Structural consequence: a rejected envelope cannot reach the sandbox — there
is no code path from the listener to the inbox except through verification
and peer authorization.

## Backend parity

| Concern | Docker | Firecracker |
|---|---|---|
| Public listener + verification | host process (backend not involved) | identical |
| Sandbox→gate route | Squid ACL: gate host + gate ports (`constle_gate_*`) | nftables accept: guest → TAP gateway on gate ports |
| Gate binding | `gateBindCandidates` (loopback + host-gateway IP) | TAP gateway IP |
| Env injection | `CONSTLE_A2A_URL` (token included) | same, via workspace image |

The MCP and A2A gates share one routing mechanism; the per-run Squid/nftables
rules take a list of gate ports (one per gate). Backends fail closed when
a2a peers are declared but no gate is attached (same rule as MCP).

## Envelope format

JSON with `sig` as the **last declared field**, adopting `audit.Entry`'s
convention verbatim: the Ed25519 signature covers the serialized envelope
with `sig` absent, and a verifier recovers those exact bytes by trimming the
`,"sig":"…"}` suffix from the wire bytes — no re-canonicalization.

```json
{"from":"did:key:z…","to":"did:key:z…","msg_id":"…","in_reply_to":"…",
 "timestamp":"…","body":{…},"sig":"base64…"}
```

- Keys: the verification key is recovered from the `from` DID itself
  (`pkg/did`); no registry, no resolution service, no new crypto.
- Responses set `in_reply_to` to the request's `msg_id`; the caller rejects
  a response not bound to its request.
- `body` must be valid JSON (enforced at the gate) so the envelope
  serializes deterministically.

## Replay protection — named limitation

Receivers reject envelopes whose timestamp is outside a ±5 minute window,
and reject a `msg_id` they have already accepted.

**LIMITATION (by design, stated rather than implied):** the seen-`msg_id`
set is **in-memory and per-run only**. It does not survive a constle process
restart and is not shared across runs. A validly signed envelope captured in
one run can be replayed against a *later* run while still inside the
timestamp window. Durable cross-run replay state is out of scope for this
version; operators who need stronger guarantees must rotate identities or
separate runs by more than the window.

## Fail-closed validation

`Validate()` rejects (errors, never warnings):

- `a2a.*` declared without `identity.did` (nothing to sign with);
- a peer endpoint host that also appears in `network.allowed_hosts`
  (would bypass the signing gate — same rule as `mcp.servers`);
- host loopback aliases in `allowed_hosts` when peers are declared
  (would expose the gate transport wholesale);
- `a2a.listen` without peers (no sender could ever be authorized);
- malformed peer DIDs/endpoints, duplicate names, duplicate DIDs, a peer
  DID equal to the agent's own.

## Audit events

Following the `gate_*` pattern; signed and hash-chained (A2A always runs
with a declared identity):

- `a2a_call_sent` — sender side: peer alias, destination DID, `msg_id`;
- `a2a_call_received` — receiver side, after full verification;
- `a2a_call_rejected` — receiver side (or sender side for a bad response),
  with a machine-readable `reason`: `malformed_envelope`, `bad_signature`,
  `unknown_peer`, `wrong_recipient`, `stale_timestamp`, `replay`.
