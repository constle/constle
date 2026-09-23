## What & Why

<!-- What does this PR do and why is it the right change?
     Link to the issue it resolves: Closes #N -->

## Changes

- 
- 

## Testing

<!-- How did you verify this? What should reviewers test? -->

- [ ] `go test ./...` passes
- [ ] `constle validate` works on the affected manifest examples
- [ ] Manual smoke test (describe what you ran)

## Checklist

- [ ] No secrets or credentials in diff
- [ ] Commit identity checked in the exact worktree every commit was made from: `git config --local user.name` and `git config --local user.email` show the project identity, and `git log --format='%an <%ae> / %cn <%ce>' origin/main..HEAD` shows nothing else
- [ ] YAML spec changes are reflected in examples
- [ ] CLI `--help` text updated if flags changed
- [ ] Breaking changes are called out explicitly
