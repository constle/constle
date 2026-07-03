# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately using [GitHub Security Advisories](https://github.com/constle/constle/security/advisories/new). This keeps the details confidential until a fix is ready.

Include as much of the following as you can:

- A description of the vulnerability and its potential impact
- The component affected (runtime, CLI, spec, identity/KYA, spending enforcement)
- Steps to reproduce or a minimal proof-of-concept
- Any suggested mitigations you have identified

You do not need a working exploit to report. If you are unsure whether something is a security issue, report it privately and we will triage together.

---

## Response Timeline

| Event | Target |
|-------|--------|
| Acknowledgement | Within 48 hours |
| Initial triage and severity assessment | Within 7 days |
| Fix or mitigation for critical/high issues | Within 30 days |
| Fix or mitigation for medium issues | Within 90 days |
| Fix or mitigation for low/informational | Best effort |

We will keep you informed of progress throughout. If we need more information we will reach out via the advisory thread.

---

## Disclosure Policy

Constle follows **coordinated disclosure**:

1. You report privately via GitHub Security Advisories.
2. We triage, develop a fix, and prepare a release.
3. We coordinate a disclosure date with you — default embargo is **90 days** from the date of the initial report.
4. On the disclosure date, we publish the fix, release a new version, and open the advisory publicly with full credit to the reporter (unless you prefer to remain anonymous).

If the embargo needs to extend beyond 90 days (for example, because the fix requires a protocol-level change across multiple components), we will discuss this with you before the deadline passes.

We will never ask you to extend the embargo indefinitely or to withhold information that is already publicly known.

---

## Scope

The following are in scope for security reports:

### Runtime & Sandbox
- Sandbox escape: an agent process breaking out of its Firecracker microVM or gVisor container
- Resource limit bypass: an agent consuming CPU, memory, disk, or network beyond its declared limits
- Network egress bypass: an agent reaching hosts not listed in `capabilities.network.allowed_hosts`
- Filesystem mount bypass: an agent reading or writing paths outside its declared mounts
- Secret leakage: secrets injected at `/run/secrets` accessible outside the sandbox

### CLI (`constle` binary)
- Command injection via manifest fields parsed by the CLI
- Path traversal when processing manifest file paths
- Privilege escalation during sandbox provisioning

### Agent Manifest & Spec
- Fields whose semantics create an exploitable gap between what the manifest declares and what the runtime enforces
- Spec ambiguities that allow a malicious manifest author to deceive a runtime operator about what an agent will do

### Identity & KYA
- DID signature verification bypass
- Trust chain manipulation (forging a parent/child DID relationship)
- KYA registry spoofing or poisoning

### Spending Enforcement (x402 / AP2)
- Spending limit bypass: an agent spending more than `max_per_run_usd` or `max_per_day_usd`
- Payment interceptor evasion: an agent making payments without going through the runtime's x402 proxy

### Human Gates
- Gate bypass: an agent performing an action that requires human approval without receiving it
- Gate notification forgery: triggering false approvals via the webhook endpoint

---

## Out of Scope

The following are **not** in scope:

- **Denial of service** against the Constle runtime itself (resource exhaustion by a legitimate operator-level user)
- **Third-party dependencies**: vulnerabilities in upstream packages (Go stdlib, Firecracker, gVisor, cobra). Report these to the upstream project. We will update our dependencies when fixes are available.
- **Social engineering** of maintainers or contributors
- **Speculative attacks** with no demonstrated impact (e.g., theoretical timing side-channels with no working PoC)
- **Issues in documentation only** (typos, inaccurate descriptions) — open a public issue
- **Protocol-level weaknesses in MCP, A2A, ACP, or x402** — report these to the respective protocol maintainers. If the weakness is in how Constle *implements* a protocol, that is in scope.
- **`--sandbox=none` mode** — this mode explicitly disables isolation and is documented as unsafe for production use

---

## Safe Harbor

Constle is an open-source project with no commercial entity behind it. We cannot offer monetary rewards at this time.

We commit to:
- Publicly crediting reporters in the security advisory (unless anonymity is requested)
- Not pursuing legal action against researchers who discover and responsibly disclose vulnerabilities in good faith
- Working collaboratively with reporters rather than treating disclosure as an adversarial event

We ask that reporters:
- Give us a reasonable amount of time to respond before any public disclosure
- Avoid accessing, modifying, or destroying data beyond what is necessary to demonstrate the vulnerability
- Limit testing to systems you own or have explicit permission to test against

---

## Supported Versions

During the pre-1.0 phase, only the latest release receives security fixes. Once v1.0 ships, we will publish a support matrix here.

| Version | Supported |
|---------|-----------|
| latest (`main`) | Yes |
| older releases | No |
