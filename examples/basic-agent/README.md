# basic-agent

Minimal Constle example. Reads `AGENT_TASK` from the environment, calls
`claude-haiku-4-5-20251001`, and prints the response to stdout.

## Files

| File | Purpose |
|------|---------|
| `agent.py` | The agent code |
| `Dockerfile` | Builds the container image |
| `agent.yaml` | Agentfile — declares sandbox, network policy, and capabilities |

## Quick start

```bash
# 1. Build the image
docker build -t basic-agent:latest .

# 2. Run with Constle (enforces network policy via Squid proxy)
export ANTHROPIC_API_KEY=sk-ant-...
constle run agent.yaml --env AGENT_TASK="What is 2+2?"

# 3. Or run directly (no network isolation)
docker run --rm \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -e AGENT_TASK="What is 2+2?" \
  basic-agent:latest
```

## Network policy

`agent.yaml` sets `egress: restricted` with `allowed_hosts: [api.anthropic.com]`.
When Constle runs the container, a Squid proxy sits between the agent and the
internet and blocks every destination except `api.anthropic.com`. Direct IP
connections are also denied, preventing hostname-bypass attacks.

## How Constle passes the API key

Constle reads `ANTHROPIC_API_KEY` from the host shell and injects it into the
container with `docker run -e ANTHROPIC_API_KEY=...`. The key is never written
to the image or to the Agentfile.
