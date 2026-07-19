// Package spending implements runtime enforcement of the manifest's
// spending limits: exact cost metering at the MCP gate, per-run caps, and a
// durable per-DID daily ledger shared across independent `constle run`
// processes.
//
// ============================================================
// Design decisions (Phase 0 of the spending-enforcement feature)
//
//  1. METERING POINT — the MCP gate proxy only, never TLS interception.
//     Cost is measured exclusively for traffic routed through the mcpgate
//     proxy, which already terminates TLS on the agent's behalf as a reverse
//     proxy and therefore already sees plaintext responses. Injecting a CA
//     certificate into the sandbox to decrypt arbitrary allowed_hosts
//     traffic is REJECTED as an architectural direction (not deferred): it
//     would let Constle read everything the agent sends and receives — a far
//     larger privacy surface than cost metering requires. The corollary is
//     surfaced, not hidden: traffic through network.allowed_hosts is NOT
//     metered, and the CLI prints an explicit "declared but NOT enforced"
//     warning (same pattern as warnUnenforcedHumanGates) whenever spending
//     limits exist without priced MCP servers to measure them.
//
//  2. PRICING IS DECLARED, NEVER GUESSED. Each mcp.servers entry may carry a
//     pricing block with a list of meters — {usage_path, usd_per_unit} — so
//     the metering code stays generic and needs no per-provider knowledge.
//     usage_path is a minimal dot-separated path (a digit segment indexes an
//     array; no wildcards, no expression language) evaluated against the
//     full JSON-RPC tools/call response — the same "exact, deterministic,
//     auditable mapping" principle as the human-gate tool-name contract.
//     Meters are a LIST because real API pricing separates input and output
//     units at different rates; the cost of a response is the sum over all
//     meters. Pricing is SERVER-WIDE by design: it applies to every
//     tools/call response of that server, so a priced server cannot expose
//     an "unpriced" tool — a response missing the declared usage value is a
//     metering failure and fails closed (kills the run), because otherwise a
//     malicious or buggy server could zero its own bill by omitting the
//     usage field (the inverse of the usage-inflation attack). Stated
//     limitation: to mix free and priced tools from one upstream, declare
//     the same URL twice under two server ids with disjoint tools
//     allowlists — one priced, one not.
//
//  3. ENFORCEMENT ACTION — the existing kill path. A limit violation trips
//     the gate (every subsequent request is rejected at the proxy, so the
//     agent cannot complete another call even before the kill lands) and
//     fires the same backend.Kill() path used by max_duration_seconds. No
//     parallel kill mechanism exists.
//
//  4. DAILY TRACKING IS DURABLE, KEYED BY DID. Per-day spend must survive
//     across independent `constle run` processes, so it lives in an
//     append-only JSONL ledger under ~/.constle/spending/<did>/<UTC date>,
//     keyed by the agent's DID (renaming an agent cannot reset tracking —
//     max_per_day_usd therefore requires identity.did, fail closed at
//     validation). Every append holds an exclusive flock and recomputes the
//     day total from the file, so two concurrent runs of the same DID
//     serialize their charges and enforce the shared cap correctly. All
//     directories and files go through homedir.MkdirAllOwned /
//     ChownToInvokingUser so a sudo (Firecracker) run never leaves
//     root-owned state in the invoking user's home.
//
//  5. EXACT ACCOUNTING — integer micro-cents (1 µ¢ = 1e-8 USD) in int64,
//     never float64. Manifest USD strings are parsed by an exact decimal
//     parser (more than 8 fractional digits is a validation error, not a
//     silent rounding); per-charge usage×price is computed in big.Rat and
//     rounded UP to the next micro-cent (enforcement must never
//     undercount); accumulation is plain integer addition, so any number of
//     small charges sums with zero drift.
//
// ============================================================
package spending
