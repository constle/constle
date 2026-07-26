# Constle Roadmap

Constle ships in milestones, not on a calendar. Each milestone is scoped narrowly enough to land as working, tested software rather than accumulate half-finished features.

---

## Shipped

- **Sandboxed execution** - Firecracker microVM and Docker backends, network egress allowlisting via a proxy the agent cannot bypass
- **Cryptographic identity** - W3C `did:key` (Ed25519), signed and hash-chained audit logs
- **Human gate policies** - enforced at the MCP gate proxy layer, with a safe abort-on-timeout default
- **Spending enforcement** - hard per-run and per-day limits enforced by the runtime, metered per priced MCP server
- **Agent-to-agent communication** - signed messaging restricted to declared peers
- **CLI** - `run`, `validate`, `ps`, `stop`, `init`, `identity`, `audit verify`

## In progress

We're moving from "the runtime works" to "the runtime is trustworthy at a glance": deeper conformance testing, a field-by-field specification of what each manifest key actually enforces versus declares, and hardening the paths that touch real infrastructure.

## Exploring

Once identity and spending enforcement are solid, agent-to-agent commerce becomes possible - agents discovering and paying each other for work. This is a direction we're thinking about, not a scheduled milestone.

---

## Influencing the roadmap

Open an [RFC issue](https://github.com/constle/constle/issues/new?template=rfc.md) to propose a change in priority. This file changes as the project does - PRs to it are welcome.
