# A2A — Signed Agent-to-Agent Communication

Status: complete. Phases 1–4 implemented and verified end to end on both
the Docker and Firecracker backends (outbound, inbound listener/inbox, audit
completeness, adversarial verification).

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
5. bounded inbox with a **per-peer admission quota**: each declared peer
   may hold at most a fixed number of undelivered calls; exceeding it sheds
   that peer's calls (503) without affecting any other peer, so a noisy or
   buggy — but fully authenticated — peer cannot starve an unrelated one,
   and total host memory stays bounded by (quota × declared peers).

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
with a declared identity). Three event types, governed by one invariant:

> Every signed envelope leaving this host is audited as `a2a_call_sent`;
> every envelope arriving and passing full verification as
> `a2a_call_received`; every round trip that does not complete as
> `a2a_call_rejected` with the precise reason. "Verified" is not a separate
> event — it is the precondition of `received`.

A completed round trip therefore produces four symmetric entries, and each
side's log alone shows its half closing (`in_reply_to` quoting the request
`msg_id`):

| side | event | key details |
|---|---|---|
| caller | `a2a_call_sent` | `direction:"request"`, peer, to_did, msg_id |
| callee | `a2a_call_received` | `direction:"request"`, peer, from_did, msg_id |
| callee | `a2a_call_sent` | `direction:"response"`, peer, to_did, msg_id, in_reply_to |
| caller | `a2a_call_received` | `direction:"response"`, peer, from_did, msg_id, in_reply_to |

`a2a_call_rejected` means "this round trip did not complete, for reason X",
on whichever log records it; `direction` names the failed leg. Reasons:

- verification: `malformed_envelope`, `bad_signature`, `unknown_peer`
  (with the *claimed*, unverified sender DID), `wrong_recipient`,
  `stale_timestamp`, `replay`, `inbox_full`;
- transport: `peer_unreachable`, `peer_http_error`, `reply_timeout`,
  `peer_disconnected`. These exist because peers usually run on separate
  machines under different operators: without them, a sender's log would
  end at `a2a_call_sent` forever, indistinguishable from a completion
  recorded on a log its operator cannot see.

## Adversarial verification

Phase 4 proves the enforcement holds under attack, using the project's
existing conformance methodology (a ground-truth target attacked from inside
a real sandbox, every scenario run on both backends with parity asserted).
The tests live in `internal/sandbox/a2a_conformance_test.go` and
`a2a_twoprocess_test.go`, gated behind `CONSTLE_E2E=1`:

- **Undeclared DID / forged signature never reach the sandbox.** A call
  signed by an undeclared identity and a tampered call are both rejected at
  B's host listener (403). B's *sandbox* is the ground truth — an inbox
  drainer that echoes every body it receives — and it records only the one
  genuine declared-peer call, never the attacker payloads. The proof is the
  sandbox never seeing them, not merely that the host returned an error.

- **Direct sandbox access fails at the network layer.** An attacker running
  in its own sandbox tries to inject a call directly into B — at B's sandbox
  address and at B's public listener, both via the egress proxy and with
  proxy env unset. Every attempt fails at the network layer (no route /
  refused) and B's sandbox records nothing. B's sandbox exposes no inbound
  A2A port on either backend; the only ingress is B's host listener, which
  verifies.

- **Two-process signed round trip.** Two independent `constle run`
  invocations — separate OS processes, separate DIDs, separate audit logs,
  each declaring the other — complete a genuine signed, mutually
  authenticated round trip.

- **Two-process replay.** Against a real running receiver, the exact same
  validly signed envelope sent twice within one run is accepted once and
  rejected the second time by the in-memory `msg_id` guard; the sandbox sees
  it once. (This is the per-run guard whose limitation is named above — it
  does not span runs or restarts.)
