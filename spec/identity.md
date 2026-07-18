# Agent Identity and Signed Audit Logs

Design document for Constle's cryptographic agent identity: how an agent gets a
DID, where its key lives, and how the audit log becomes tamper-evident. This is
the foundation the future agent-to-agent (A2A) verification work builds on.

---

## DID method: `did:key` (Ed25519)

An agent identity is expressed as a standard
[did:key](https://w3c-ccg.github.io/did-method-key/) identifier:

```
did:key:z<base58btc( varint(0xed) || 32-byte Ed25519 public key )>
```

- `0xed` is the [multicodec](https://github.com/multiformats/multicodec) code
  for `ed25519-pub`, varint-encoded as the two bytes `0xed 0x01`.
- `z` is the [multibase](https://github.com/multiformats/multibase) prefix for
  base58btc.

### Why did:key

**Self-describing.** The identifier *is* the public key. Any party — the
`constle audit verify` command today, a remote Constle runtime during A2A
verification tomorrow — recovers the verification key directly from the DID
string. No resolution service, no registry, no network call, nothing to trust
except the string itself.

**Standard, not invented.** `did:key` is the established method for exactly
this use case. A non-Constle verifier with any standard DID library can check
Constle signatures without reading our source code.

**Dependency-free.** The open core stays lean: Ed25519 and SHA-256 come from
the Go standard library, and the base58btc/varint encoding is ~60 lines
implemented in `pkg/did`, pinned by test vectors from an independent
implementation — including the classic leading-zero-byte base58 edge cases.

### Out of scope (deliberately)

- Full W3C DID document resolution — `did:key` needs none.
- Key rotation and revocation — a did:key identifier is its key; rotation
  means a new identity.
- Cross-machine identity portability.

---

## Identity lifetime and storage

An identity is **per-agent, persistent across runs** — not per-run. It is
created once with `constle identity create <name>` and bound to
`identity.name` and (optionally) an owner.

```
~/.constle/identities/<agent-name>/     mode 0700
├── key.pem        Ed25519 private key, PKCS#8 PEM, mode 0600
└── identity.json  public metadata: did, owner, created_at
```

Rules, all enforced in code (`internal/identity`):

- **The private key never appears in the Agentfile** — only the public DID
  string does, following the same indirection pattern as `url_secret_ref`.
  It also never appears in audit logs and never leaves the machine.
- **Permissions are checked at every load, not just at creation.** If
  `key.pem` is not exactly mode 0600 — a umask drift, a backup restore, a
  shared machine — loading fails closed with instructions to `chmod 600`.
- **The stored DID must match the stored key.** `identity.json` records the
  DID; if the private key on disk derives a different one (swapped or
  corrupted key file), loading fails closed.
- **Owner binding.** If both the Agentfile and the stored identity declare an
  owner and they differ, the run is refused.
- **sudo-aware.** The Firecracker backend runs constle as root; identities
  (like audit logs) always resolve to the invoking user's home via
  `internal/homedir`, so all runs of an agent share one identity.

### Fail closed

A declared protection must never look real when it isn't (the same principle
as unenforced human-gate warnings). If an Agentfile declares `identity.did`:

- `constle run` **refuses to start** when the matching local private key is
  missing, unreadable, mis-permissioned, or derives a different DID.
- `constle validate` warns that the identity is not usable on this machine.

---

## Signed, hash-chained audit log

When the agent has an identity, every JSONL audit entry — including the
enforcement events `network_blocked`, `network_allowed`, `gate_triggered`,
`gate_approved`, `gate_denied`, `gate_timeout`, and `mcp_tool_blocked` —
carries three extra fields, written by the same single logger that writes
every other event (one mechanism, not two):

| Field | Content |
|-------|---------|
| `did` | the signing agent's did:key identifier |
| `prev_hash` | hex SHA-256 of the previous raw log line; an all-zero genesis value for the first line of a file |
| `sig` | base64 Ed25519 signature over the serialized entry (with `sig` itself absent) |

Because `sig` is always the **last** JSON field, the signed bytes are exactly
the raw line minus the `,"sig":"…"}` suffix. Verification operates on the very
bytes on disk — no re-canonicalization, so no canonicalization bugs.

The hash chain is what makes the log tamper-evident as a *sequence* rather
than a set of independently signed lines:

- **editing** a line breaks its signature (`invalid_signature`, exact line);
- **deleting** a line leaves the next line chaining to a hash that no longer
  exists (`chain_break_missing_entry`, exact position);
- **reordering** lines leaves a line chaining to a hash found elsewhere in
  the file (`chain_break_reordered`, exact position);
- **rewriting the whole log** with a different key is internally consistent
  but fails against the pinned DID (`did_mismatch` — pin with
  `constle audit verify --did=…` or compare against the Agentfile).

The chain resumes across runs within a log file: a new run's first entry
chains to the last line already in the file.

`constle audit verify <logfile>` checks every signature (key recovered from
the DID string, no external service) and the whole chain, and reports the
exact line and kind of tampering on failure.
