#!/bin/sh
# hygiene-check.sh — scan git history and the working tree for content that
# must never reach the public repository: AI-attribution trailers, plus the
# maintainer-private identifiers and non-ASCII byte ranges loaded from a
# private pattern file.
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
#   1. Generic patterns (below, checked in): AI-attribution phrases, and
#      nothing else. They describe a tool's output, not a person or a place,
#      which is the whole reason they can sit in a public file.
#
#      The bar for this list is not "does it name someone" but "does it
#      narrow who someone is". A pattern is a description of what is being
#      hidden, so a check that names nobody can still give away more than the
#      content it is looking for. Anything that fails that second test belongs
#      in the private file, however harmless it reads.
#
#   2. Private patterns (NOT checked in): the maintainer's personal
#      identifiers — name variants, hostname strings — and any non-ASCII byte
#      ranges to watch for; anything that would itself be a leak if this
#      script shipped it. One case-insensitive extended regex per line,
#      # comments allowed, loaded from:
#          $CONSTLE_HYGIENE_PATTERNS  (if set), else
#          ~/.config/constle/hygiene-patterns
#
#      A line may carry an optional scope prefix:
#          text:<regex>   checked in text content only
#          <regex>        checked in every file, text or binary
#      Scope exists for byte-range patterns. A range over raw bytes matches
#      compressed binary content by coincidence — a two-byte range covers
#      roughly 0.1% of random byte pairs, which is thousands of hits per
#      megabyte of compressed data — so on a binary such a pattern reports
#      nothing but noise, and a scan that is permanently red is a scan nobody
#      reads. Phrase patterns take no prefix and are checked everywhere.
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
# Generic, publishable patterns — see PATTERN SOURCES above for what is
# allowed to live here. Case-insensitive extended regexes, one per entry.
# Scoped to attribution PHRASES, not bare product words: this repo
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

PRIVATE_FILE="${CONSTLE_HYGIENE_PATTERNS:-$HOME/.config/constle/hygiene-patterns}"
REQUIRE_PRIVATE=0
STATUS=0

warn() { printf '%s\n' "hygiene-check: $*" >&2; }

# combined_pattern_file writes the active patterns to two temp files for
# grep -f, one per line:
#
#   $1  every-file patterns  — generic entries plus unprefixed private ones
#   $2  text-only patterns   — private entries carrying the text: prefix
#
# A blank line in a grep -f file matches EVERY line, so blank lines are
# stripped on the way in and each file is only used when it is non-empty.
combined_pattern_file() {
    tmp="$1"
    text_tmp="$2"
    printf '%s\n' "$GENERIC_PATTERNS" > "$tmp"
    : > "$text_tmp"
    if [ -f "$PRIVATE_FILE" ]; then
        # LC_ALL=C and -a are both load-bearing, and their absence FAILS
        # SILENTLY. A byte-range entry puts improperly-encoded bytes in the
        # private file, which makes grep classify the file ITSELF as binary
        # and stop reproducing its lines. The byte-range entry is then dropped
        # on the way in — always — and whether its neighbours survive varies
        # with buffering and grep version, so the loaded set is both short and
        # unpredictable. A dropped entry is a check that stops running without
        # saying so, which is the failure this script exists to prevent. -a
        # forces the text path; LC_ALL=C stops the locale reaching the same
        # conclusion on its own. The count guard below is the backstop.
        LC_ALL=C grep -a -vE '^[[:space:]]*(#|$)' "$PRIVATE_FILE" > "$TMPDIR_HC/private" || true
        sed -n 's/^text://p' "$TMPDIR_HC/private" | LC_ALL=C grep -a -v '^$' >> "$text_tmp" || true
        LC_ALL=C grep -a -v '^text:' "$TMPDIR_HC/private" | LC_ALL=C grep -a -v '^$' >> "$tmp" || true

        # Every private pattern line must land in exactly one of the two
        # files. A count that does not add up means a pattern was dropped on
        # the way in, and a dropped pattern is a check that silently stops
        # running — the failure this whole script exists to prevent. Fail
        # loudly rather than scan with a short list.
        want=$(LC_ALL=C grep -a -c '' "$TMPDIR_HC/private" 2>/dev/null || echo 0)
        got_all=$(LC_ALL=C grep -a -c '' "$tmp" 2>/dev/null || echo 0)
        got_text=$(LC_ALL=C grep -a -c '' "$text_tmp" 2>/dev/null || echo 0)
        generic=$(printf '%s\n' "$GENERIC_PATTERNS" | LC_ALL=C grep -a -c '')
        if [ "$((got_all - generic + got_text))" -ne "$want" ]; then
            warn "private pattern file $PRIVATE_FILE: $want pattern line(s) present but $((got_all - generic + got_text)) loaded — refusing to scan with an incomplete pattern set"
            exit 2
        fi
    elif [ "$REQUIRE_PRIVATE" = 1 ]; then
        warn "private pattern file $PRIVATE_FILE not found and --require-private is set"
        exit 2
    else
        warn "WARNING: private pattern file $PRIVATE_FILE not found — running generic checks only"
    fi
}

# is_binary reports whether a file holds a NUL byte in its first 8000 bytes —
# git's own heuristic, reused so this script agrees with what git calls binary.
# Written with tr and wc rather than grep -I so it does not depend on a GNU
# extension the rest of the script can otherwise live without.
is_binary() {
    head -c 8000 "$1" > "$TMPDIR_HC/head" 2>/dev/null || return 1
    raw=$(wc -c < "$TMPDIR_HC/head")
    stripped=$(LC_ALL=C tr -d '\000' < "$TMPDIR_HC/head" | wc -c)
    [ "$raw" -ne "$stripped" ]
}

# scan_stream NAME reads content on stdin and reports hits under label NAME.
# Returns 0 when clean.
#
# KNOWN LIMITATION — text-scoped patterns and binary metadata. The every-file
# patterns below reach inside a binary: grep scans the whole byte stream, so a
# phrase sitting in an image's embedded metadata block, or in bytes trailing
# the image data, is found and reported. The text-scoped patterns do NOT reach
# there, because they are skipped on binary content wholesale. Real text does
# live in binary metadata — EXIF and XMP fields, container comment blocks,
# appended trailers — and a text-scoped pattern will not match it there. The
# scan is deliberately not extended to cover it: a byte-range pattern cannot
# tell metadata apart from compressed payload, so covering the first would
# re-admit the coincidental matches from the second, which is what the scope
# prefix exists to avoid. Binary metadata therefore remains a hand check.
scan_stream() {
    label="$1"
    content="$2"     # path to a file holding the content to scan
    clean=0

    # 2>&1: GNU grep reports a binary-file match ("binary file X matches")
    # on stderr with nothing on stdout, so a binary file with a hit would
    # read as clean unless stderr is captured too.
    hits=$(LC_ALL=C grep -inE -f "$PATTERN_FILE" "$content" 2>&1 | head -20) || true
    if [ -n "$hits" ]; then
        printf '✗ %s: identity/attribution pattern hits:\n%s\n' "$label" "$hits"
        clean=1
    fi

    [ -s "$TEXT_PATTERN_FILE" ] || return $clean

    if is_binary "$content"; then
        printf '• %s: binary — every-file patterns checked, text-scoped patterns skipped\n' "$label"
        return $clean
    fi

    text_hits=$(LC_ALL=C grep -inE -f "$TEXT_PATTERN_FILE" "$content" 2>&1 | head -5) || true
    if [ -n "$text_hits" ]; then
        printf '✗ %s: text-scoped pattern hits:\n%s\n' "$label" "$text_hits"
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
TEXT_PATTERN_FILE="$TMPDIR_HC/patterns-text"
combined_pattern_file "$PATTERN_FILE" "$TEXT_PATTERN_FILE"

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
