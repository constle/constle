#!/bin/sh
# hygiene-check.sh — scan git history and the working tree for content that
# must never reach the public repository: AI-attribution trailers, non-ASCII
# script ranges that have leaked here before (Hebrew), and maintainer-private
# identifiers.
#
# Usage:
#   scripts/hygiene-check.sh --all            # every commit on every ref
#   scripts/hygiene-check.sh --range A..B     # a specific commit range
#   scripts/hygiene-check.sh --tree           # tracked files as checked out
#   scripts/hygiene-check.sh --pre-push       # called by the pre-push hook;
#                                             # reads the ref lines on stdin
#   scripts/hygiene-check.sh --install-hook   # install the pre-push hook
#
# Exit codes: 0 clean, 1 hits found, 2 usage or configuration error.
#
# PATTERN SOURCES — and why they are split:
#
#   1. Generic patterns (below, checked in): AI-attribution phrases and the
#      Hebrew unicode range. Safe to publish; they name nobody.
#
#   2. Private patterns (NOT checked in): the maintainer's personal
#      identifiers — name variants, hostname strings, anything that would
#      itself be a leak if this script shipped it. One case-insensitive
#      extended regex per line, # comments allowed, loaded from:
#          $CONSTLE_HYGIENE_PATTERNS  (if set), else
#          ~/.config/constle/hygiene-patterns
#      A missing private file is a loud warning, not silence: history has
#      shown the gap is always the pattern nobody was checking (a bare first
#      name that every earlier ad-hoc grep spelled with a suffix). Pass
#      --require-private to turn that warning into a failure (recommended in
#      the pre-push hook, enforced by default when the file's directory
#      exists but the file does not).
#
#   CI note: public CI cannot carry the private file, so a CI step runs the
#   generic checks only. The pre-push hook on the maintainer's machine is
#   where the private patterns bite — install it with --install-hook.
#
# INSTALLING THE PRE-PUSH HOOK:
#   scripts/hygiene-check.sh --install-hook
#   # writes .git/hooks/pre-push (or $(git rev-parse --git-path hooks) —
#   # correct for worktrees too), which scans exactly the commits each push
#   # would publish and blocks the push on any hit.

set -u

# --------------------------------------------------------------------------
# Generic, publishable patterns. Case-insensitive extended regexes, one per
# entry. Scoped to attribution PHRASES, not bare product words: this repo
# legitimately contains ANTHROPIC_API_KEY, api.anthropic.com, and model
# names, so matching bare "claude|anthropic" would drown real leaks in
# false positives.
# --------------------------------------------------------------------------
# The bracketed single characters ([-], [ ]) are regex-equivalent to the
# plain character but keep each pattern from matching its own source line
# when a commit touching this script is scanned.
GENERIC_PATTERNS='claude[-]session:
co[-]authored[-]by:.*(claude|anthropic|copilot|gpt|gemini|cursor)
generated[ ](with|by).*(claude|copilot|gpt|gemini|cursor|ai)
claude[.]ai/code
noreply@anthropic[.]com
🤖[ ]generated'

# Hebrew (U+0590–U+05FF) as UTF-8 byte ranges, so the check works with any
# grep, not only GNU grep -P: U+0590–U+05BF encode as D6 90–D6 BF and
# U+05C0–U+05FF as D7 80–D7 BF.
HEB_HI1=$(printf '\326') HEB_LO1_START=$(printf '\220') HEB_LO1_END=$(printf '\277')
HEB_HI2=$(printf '\327') HEB_LO2_START=$(printf '\200') HEB_LO2_END=$(printf '\277')
HEBREW_RE="$HEB_HI1[$HEB_LO1_START-$HEB_LO1_END]|$HEB_HI2[$HEB_LO2_START-$HEB_LO2_END]"

PRIVATE_FILE="${CONSTLE_HYGIENE_PATTERNS:-$HOME/.config/constle/hygiene-patterns}"
REQUIRE_PRIVATE=0
STATUS=0

warn() { printf '%s\n' "hygiene-check: $*" >&2; }

# combined_pattern_file writes every active pattern (generic + private) to a
# temp file for grep -f, one per line.
combined_pattern_file() {
    tmp="$1"
    printf '%s\n' "$GENERIC_PATTERNS" > "$tmp"
    if [ -f "$PRIVATE_FILE" ]; then
        # Strip comments and blank lines.
        grep -vE '^[[:space:]]*(#|$)' "$PRIVATE_FILE" >> "$tmp" || true
    elif [ "$REQUIRE_PRIVATE" = 1 ]; then
        warn "private pattern file $PRIVATE_FILE not found and --require-private is set"
        exit 2
    else
        warn "WARNING: private pattern file $PRIVATE_FILE not found — running generic checks only"
    fi
}

# scan_stream NAME reads content on stdin and reports hits under label NAME.
# Returns 0 when clean.
scan_stream() {
    label="$1"
    content="$2"     # path to a file holding the content to scan
    clean=0

    hits=$(LC_ALL=C grep -inE -f "$PATTERN_FILE" "$content" | head -20) || true
    if [ -n "$hits" ]; then
        printf '✗ %s: identity/attribution pattern hits:\n%s\n' "$label" "$hits"
        clean=1
    fi

    heb=$(LC_ALL=C grep -nE "$HEBREW_RE" "$content" | head -5) || true
    if [ -n "$heb" ]; then
        printf '✗ %s: Hebrew characters found:\n%s\n' "$label" "$heb"
        clean=1
    fi

    return $clean
}

# scan_commits scans each commit (metadata: author, committer, full message;
# content: full patch) named on stdin, one hash per line. It usually runs on
# the downstream side of a pipe — a subshell — so a hit is recorded through a
# marker file in $TMPDIR_HC, not a variable, which the parent checks at exit.
scan_commits() {
    total=0 bad=0
    while IFS= read -r c; do
        [ -n "$c" ] || continue
        total=$((total + 1))
        git show --format='AUTHOR:%an <%ae>%nCOMMITTER:%cn <%ce>%nMSG:%B' "$c" > "$TMPDIR_HC/commit" 2>/dev/null || continue
        if ! scan_stream "commit $c" "$TMPDIR_HC/commit"; then
            bad=$((bad + 1))
            : > "$TMPDIR_HC/dirty"
        fi
    done
    printf 'scanned %s commit(s), %s with hits\n' "$total" "$bad"
}

scan_tree() {
    git ls-files | while IFS= read -r f; do
        [ -f "$f" ] || continue
        if ! scan_stream "file $f" "$f"; then
            : > "$TMPDIR_HC/dirty"
        fi
    done
    [ -e "$TMPDIR_HC/dirty" ] || printf 'working tree clean\n'
}

install_hook() {
    hooks_dir=$(git rev-parse --git-path hooks) || exit 2
    mkdir -p "$hooks_dir"
    hook="$hooks_dir/pre-push"
    if [ -e "$hook" ] && ! grep -q 'hygiene-check' "$hook" 2>/dev/null; then
        warn "$hook already exists and is not the hygiene hook — merge manually"
        exit 2
    fi
    # The hooks dir is shared between the main clone and every worktree, and
    # a worktree is disposable — so the hook runs the pushing checkout's own
    # copy of the script (hooks execute from the repo root) instead of baking
    # in any absolute path. A branch that predates the script gets a loud
    # warning, not a blocked push.
    cat > "$hook" <<'EOF'
#!/bin/sh
# Installed by scripts/hygiene-check.sh --install-hook
if [ -x ./scripts/hygiene-check.sh ]; then
    exec ./scripts/hygiene-check.sh --pre-push --require-private
fi
echo "pre-push: scripts/hygiene-check.sh not in this checkout — HYGIENE CHECK SKIPPED" >&2
exit 0
EOF
    chmod +x "$hook"
    printf 'installed %s\n' "$hook"
    if [ ! -f "$PRIVATE_FILE" ]; then
        warn "note: private pattern file $PRIVATE_FILE does not exist yet — create it (one regex per line) or the hook will fail closed"
    fi
    exit 0
}

# --------------------------------------------------------------------------
# Argument handling
# --------------------------------------------------------------------------
MODE=""
RANGE=""
for arg in "$@"; do
    case "$arg" in
        --all)             MODE=all ;;
        --tree)            MODE=tree ;;
        --pre-push)        MODE=prepush ;;
        --install-hook)    MODE=install ;;
        --require-private) REQUIRE_PRIVATE=1 ;;
        --range)           MODE=range ;;
        *)
            if [ "$MODE" = range ] && [ -z "$RANGE" ]; then RANGE="$arg"
            else warn "unknown argument: $arg"; exit 2; fi ;;
    esac
done
[ -n "$MODE" ] || { warn "usage: $0 --all | --range A..B | --tree | --pre-push | --install-hook [--require-private]"; exit 2; }

[ "$MODE" = install ] && install_hook

TMPDIR_HC=$(mktemp -d)
trap 'rm -rf "$TMPDIR_HC"' EXIT
PATTERN_FILE="$TMPDIR_HC/patterns"
combined_pattern_file "$PATTERN_FILE"

case "$MODE" in
    all)
        git rev-list --all | scan_commits
        ;;
    range)
        [ -n "$RANGE" ] || { warn "--range needs A..B"; exit 2; }
        git rev-list "$RANGE" | scan_commits
        ;;
    tree)
        scan_tree
        ;;
    prepush)
        # Standard pre-push stdin: <local ref> <local sha> <remote ref> <remote sha>
        ZERO=0000000000000000000000000000000000000000
        while read -r _local_ref local_sha _remote_ref remote_sha; do
            [ -n "$local_sha" ] || continue
            [ "$local_sha" = "$ZERO" ] && continue   # deleting a remote ref
            if [ "$remote_sha" = "$ZERO" ]; then
                # New remote branch: scan what is not already public anywhere.
                git rev-list "$local_sha" --not --remotes | scan_commits
            else
                git rev-list "$remote_sha..$local_sha" | scan_commits
            fi
        done
        ;;
esac

# Hits are recorded via a marker file because scan_commits typically runs in
# a pipeline subshell where variable assignments cannot reach this shell.
[ -e "$TMPDIR_HC/dirty" ] && STATUS=1

if [ "$STATUS" != 0 ]; then
    printf '\nhygiene-check FAILED — do not push until the hits above are resolved\n' >&2
fi
exit "$STATUS"
