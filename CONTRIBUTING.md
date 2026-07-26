# Contributing to Constle

Constle is early and maintained by one person right now, so response times won't always be fast — but every issue and PR gets read.

## Getting started

```bash
git clone https://github.com/constle/constle
cd constle
go build ./...
go test ./...
```

## What's most useful right now

- Bug reports with clear reproduction steps (a failing test is even better)
- A gVisor sandbox backend, alongside the existing Firecracker and Docker ones
- More example agents in `examples/`
- Gaps between `spec/agent-manifest.md` and what the parser actually accepts

## Before a PR

Open an issue first for anything beyond a small fix — it's a quick way to confirm the approach before you spend time on it. Keep PRs scoped to one change.

## Code style

- English only, including comments — no exceptions
- Standard Go conventions (`gofmt`, `go vet`)
- New behavior needs a test
