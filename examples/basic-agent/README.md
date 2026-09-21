# basic-agent

Minimal Constle example. Reads `AGENT_TASK` from the environment, calls
`llama-3.1-8b-instant` on the Groq API, and prints the response to stdout.

## Files

| File | Purpose |
|------|---------|
| `agent.py` | The agent code |
| `Dockerfile` | Builds the container image |
| `agent.yaml` | Agentfile — declares sandbox, network policy, capabilities, and credentials |

## Quick start

```bash
# 1. Build the image
docker build -t basic-agent:latest .

# 2. Run with Constle (enforces network policy via Squid proxy)
export GROQ_API_KEY=gsk_...          # free key: https://console.groq.com
export AGENT_TASK="What is 2+2?"
constle run agent.yaml

# 3. Or run directly (no network isolation, no credential scoping)
docker run --rm \
  -e GROQ_API_KEY \
  -e AGENT_TASK \
  basic-agent:latest
```

There is no `--env` flag. Everything the sandbox receives from your environment
is declared in the Agentfile.

## Network policy

`agent.yaml` sets `egress: restricted` with `allowed_hosts: [api.groq.com]`.
When Constle runs the container, a Squid proxy sits between the agent and the
internet and blocks every destination except `api.groq.com`. Direct IP
connections are also denied, preventing hostname-bypass attacks.

## How Constle passes the credentials

`agent.yaml` declares them:

```yaml
credentials:
  - name: GROQ_API_KEY
  - name: AGENT_TASK
```

Constle resolves each name from the host shell and builds the sandbox's
environment from that list. **The list is complete for your environment**:
nothing else you have exported reaches the agent, so an `ANTHROPIC_API_KEY` or
an `AWS_SECRET_KEY` you happen to have set stays on the host. Declare nothing and
the agent receives nothing. (The container still has whatever its own image sets,
plus the proxy and gate addresses constle builds for the run — those are not your
environment.)

Only the variable's *name* is in the Agentfile. The value is never written to
the image, to the Agentfile, or to the audit log — the audit log's
`run_started` entry records which names this run granted, and no values.

The value does not reach the `docker run` argv either: Constle passes `-e NAME`
with no `=` and lets the Docker client resolve it from its own environment,
because `/proc/<pid>/cmdline` is world-readable and an inline `-e NAME=value`
would publish the key to every local user.

A declared variable that is not set on the host — or is set to the empty string
— makes `constle run` refuse to start, before it creates anything.
`constle validate` warns instead, since you may be validating on a machine that
holds no keys.
