# Contributing to Constle

Constle is early and maintained by one person right now, so response times won't always be fast - but every issue and PR gets read.

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

Open an issue first for anything beyond a small fix - it's a quick way to confirm the approach before you spend time on it. Keep PRs scoped to one change.

## Code style

- English only, including comments - no exceptions
- Standard Go conventions (`gofmt`, `go vet`)
- New behavior needs a test

## Repository hygiene checks

`scripts/hygiene-check.sh` scans commits (messages, authorship, patch
content, and the embedded metadata of binary and media files) for content
that must not reach this repository. Its patterns are loaded from an
untracked file outside the repo (`~/.config/constle/hygiene-patterns`,
overridable via `CONSTLE_HYGIENE_PATTERNS`); without that file it refuses to
run. Reading embedded metadata needs `exiftool`.

CI runs the check on every PR's commit range. To also run it locally on
every push, install the pre-push hook once per clone:

```bash
scripts/hygiene-check.sh --install-hook
```

Other modes: `--all` (every commit on every ref), `--range A..B`, `--tree`
(tracked files as checked out). Exit code 1 means hits were found and
printed with their commit hashes; 2 means the check could not run in full
(no pattern file, or no `exiftool` for a file that needs it).
