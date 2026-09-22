#!/bin/sh
# hygiene-check.sh — scan git history and the working tree for content that
# must not reach the public repository.
#
# Usage:
#   scripts/hygiene-check.sh --all            # every commit on every ref
#   scripts/hygiene-check.sh --range A..B     # a specific commit range
#   scripts/hygiene-check.sh --tree           # tracked files as checked out
#   scripts/hygiene-check.sh --pre-push       # called by the pre-push hook;
#                                             # reads the ref lines on stdin
#   scripts/hygiene-check.sh --install-hook   # install the pre-push hook
#
# --require-private is accepted, for hooks that pass it, and changes nothing:
# the pattern file is always required.
#
# Exit codes: 0 clean, 1 hits found, 2 usage or configuration error —
# including a missing or empty pattern file, and a file whose embedded
# metadata needed reading and could not be read.
#
# PATTERN FILE:
#
#   No pattern is checked in. They are read from a file kept outside the
#   repository:
#       $CONSTLE_HYGIENE_PATTERNS  (if set), else
#       ~/.config/constle/hygiene-patterns
#   One case-insensitive extended regex per line, # comments allowed. Without
#   the file, or with a file that yields no patterns, the script refuses to
#   scan: a scan with nothing to look for would report clean.
#
#   A line may carry an optional scope prefix:
#       <regex>        checked everywhere: text, the raw bytes of a binary
#                      file, and embedded metadata
#       text:<regex>   checked in text content and embedded metadata, not in
#                      the raw bytes of a binary file
#       meta:<regex>   checked in embedded metadata only
#   text: exists for byte-range patterns. A range over raw bytes matches
#   compressed binary content by coincidence — a two-byte range covers
#   roughly 0.1% of random byte pairs, which is thousands of hits per megabyte
#   of compressed data — so on a binary such a pattern reports nothing but
#   noise, and a scan that is permanently red is a scan nobody reads.
#
#   CI reads the same file from a repository secret: see the hygiene job in
#   .github/workflows/ci.yaml.
#
# EMBEDDED METADATA:
#
#   Every binary file a scan reaches, and every file with a media or document
#   extension whether git calls it binary or not, is also read with exiftool,
#   and the fields it decodes are checked against every pattern. A byte scan
#   sees such a field only when the format stores it uncompressed.
#
#   exiftool is REQUIRED whenever there is such a file to read. Without it the
#   scan still runs every other check, then exits 2. A range or tree with no
#   binary or media file in it does not need exiftool at all. Install it with
#       apt-get install libimage-exiftool-perl     (Debian, Ubuntu)
#       brew install exiftool                      (macOS)
#   or point $CONSTLE_HYGIENE_EXIFTOOL at the executable.
#
# INSTALLING THE PRE-PUSH HOOK:
#   scripts/hygiene-check.sh --install-hook
#   # writes .git/hooks/pre-push (or $(git rev-parse --git-path hooks) —
#   # correct for worktrees too), which scans exactly the commits each push
#   # would publish and blocks the push on any hit.

set -u

# Every byte this script handles is a byte, never a character. The pattern
# file can hold raw byte ranges, which are not valid text in any UTF-8
# locale, and a tool that is allowed to notice that will refuse the input:
# BSD sed answers "RE error: illegal byte sequence" and stops, GNU tools
# quietly switch to their binary path. Both outcomes drop patterns.
#
# It is EXPORTED rather than prefixed per command because a prefix covers one
# command and no more — not the other side of a pipe, not a subshell, not a
# function called from there. That distinction cost a macOS CI failure: every
# grep in the loading path carried the prefix and the sed between them did
# not. One export covers the whole script, including anything added later by
# someone who does not know this paragraph exists.
export LC_ALL=C

PRIVATE_FILE="${CONSTLE_HYGIENE_PATTERNS:-$HOME/.config/constle/hygiene-patterns}"
EXIFTOOL="${CONSTLE_HYGIENE_EXIFTOOL:-exiftool}"
STATUS=0

warn() { printf '%s\n' "hygiene-check: $*" >&2; }

# count_lines prints the number of lines in a file, and prints 0 for anything
# it cannot count. It exists because the obvious spellings are both wrong:
#
#   grep -c '' FILE || echo 0    on an EMPTY file grep prints 0 AND exits 1,
#                                so the fallback fires too and the result is
#                                the two-line string "0\n0", which is not a
#                                number and takes the arithmetic below down
#                                with it. Empty is the normal case for a
#                                scope with no entries in the pattern file.
#   wc -l < FILE                 BSD wc pads its output with leading spaces,
#                                so the result is " 3" on macOS and "3" on
#                                Linux.
#
# So: count with wc, which always exits 0, strip whitespace, and refuse
# anything that is not a plain number rather than feeding it to $(( )).
count_lines() {
    n=$(wc -l < "$1" 2>/dev/null | tr -d '[:space:]')
    case "$n" in
        '' | *[!0-9]*) n=0 ;;
    esac
    printf '%s' "$n"
}

# combined_pattern_file splits the pattern file by scope into three temp
# files for grep -f, one pattern per line:
#
#   $1  every-file patterns  — unprefixed entries
#   $2  text-only patterns   — entries carrying the text: prefix
#   $3  metadata-only        — entries carrying the meta: prefix
#
# A blank line in a grep -f file matches EVERY line, so blank lines are
# stripped on the way in and each file is only used when it is non-empty.
combined_pattern_file() {
    tmp="$1"
    text_tmp="$2"
    meta_tmp="$3"
    : > "$tmp"
    : > "$text_tmp"
    : > "$meta_tmp"
    if [ ! -f "$PRIVATE_FILE" ]; then
        warn "pattern file $PRIVATE_FILE not found — refusing to scan without it"
        exit 2
    fi

    # -a is load-bearing here, and its absence FAILS SILENTLY. A byte-range
    # entry puts improperly-encoded bytes in the pattern file, which can make
    # a tool classify the file ITSELF as binary and stop reproducing its
    # lines: the entry is dropped on the way in, along with an unpredictable
    # number of its neighbours, and nothing says so. A dropped entry is a
    # check that stops running — the failure this script exists to prevent.
    # -a forces the text path; the exported LC_ALL=C at the top of the file
    # stops the locale reaching the same conclusion on its own grounds. The
    # count guard below is the backstop for both, and for whatever the next
    # tool decides to do.
    # `|| true` would swallow the difference between "no lines matched"
    # (grep exit 1, normal) and "could not read the file" (grep exit 2 —
    # unreadable, a directory, a broken symlink). Swallowing the second is how
    # an existing-but-unreadable pattern file degrades into a scan that looks
    # for nothing and prints a clean tree: the check above is satisfied by the
    # file EXISTING, and nothing downstream notices that it contributed
    # nothing.
    grep -a -vE '^[[:space:]]*(#|$)' "$PRIVATE_FILE" > "$TMPDIR_HC/private"
    rc=$?
    if [ "$rc" -gt 1 ]; then
        warn "pattern file $PRIVATE_FILE could not be read (grep exit $rc) — refusing to scan without it"
        exit 2
    fi
    sed -n 's/^text://p' "$TMPDIR_HC/private" | grep -a -v '^$' >> "$text_tmp" || true
    sed -n 's/^meta://p' "$TMPDIR_HC/private" | grep -a -v '^$' >> "$meta_tmp" || true
    grep -a -vE '^(text|meta):' "$TMPDIR_HC/private" | grep -a -v '^$' >> "$tmp" || true

    # Every pattern line must land in exactly one of the three files. A count
    # that does not add up means a pattern was dropped on the way in, and a
    # dropped pattern is a check that silently stops running — the failure
    # this whole script exists to prevent. Fail loudly rather than scan with
    # a short list.
    want=$(count_lines "$TMPDIR_HC/private")
    got_all=$(count_lines "$tmp")
    got_text=$(count_lines "$text_tmp")
    got_meta=$(count_lines "$meta_tmp")
    if [ "$((got_all + got_text + got_meta))" -ne "$want" ]; then
        warn "pattern file $PRIVATE_FILE: $want pattern line(s) present but $((got_all + got_text + got_meta)) loaded — refusing to scan with an incomplete pattern set"
        exit 2
    fi

    # A file of nothing but comments leaves nothing to scan for, and a scan
    # for nothing reports clean. That is not a state to discover afterwards
    # from a clean report.
    if [ "$want" -eq 0 ]; then
        warn "pattern file $PRIVATE_FILE contains no patterns — refusing to scan with nothing to scan for"
        exit 2
    fi
}

# is_binary reports whether a file holds a NUL byte in its first 8000 bytes —
# git's own heuristic, reused so this script agrees with what git calls binary.
# Written with tr and wc rather than grep -I so it does not depend on a GNU
# extension the rest of the script can otherwise live without.
is_binary() {
    head -c 8000 "$1" > "$TMPDIR_HC/head" 2>/dev/null || return 1
    raw=$(wc -c < "$TMPDIR_HC/head")
    stripped=$(tr -d '\000' < "$TMPDIR_HC/head" | wc -c)
    [ "$raw" -ne "$stripped" ]
}

# has_media_extension PATH reports whether PATH's extension names a format
# that carries embedded metadata. Binary files have their metadata read
# whatever they are called; this list is for the formats that can pass for
# text — PDF, SVG, PostScript, XMP sidecars — which git and is_binary both
# call text, and for any image that happens to hold no NUL in its first
# 8000 bytes.
has_media_extension() {
    ext=$(printf '%s' "${1##*/}" | tr '[:upper:]' '[:lower:]')
    case "$ext" in
        *.png | *.apng | *.jpg | *.jpeg | *.gif | *.webp | *.bmp | *.tif | *.tiff | \
        *.heic | *.heif | *.avif | *.ico | *.svg | *.psd | *.pdf | *.ps | *.eps | \
        *.ai | *.xmp | *.mp4 | *.m4v | *.mov | *.webm | *.mkv | *.avi | *.mp3 | \
        *.m4a | *.wav | *.ogg | *.flac)
            return 0 ;;
    esac
    return 1
}

# scan_stream NAME reads content on stdin and reports hits under label NAME.
# Returns 0 when clean.
#
# BINARY CONTENT. The every-file patterns reach inside a binary: grep scans
# the whole byte stream, so a phrase sitting uncompressed in an image's
# metadata block, or in bytes trailing the image data, is found here. The
# text-scoped patterns are skipped on binary content wholesale: a byte-range
# pattern cannot tell a metadata block from compressed payload, and payload
# matches it by coincidence. Neither reaches text a format stores compressed
# or encoded. Embedded metadata is therefore scan_metadata's job, not this
# function's: exiftool hands it the fields decoded and without the payload,
# so every pattern, text-scoped ones included, can be applied to them.
scan_stream() {
    label="$1"
    content="$2"     # path to a file holding the content to scan
    clean=0

    # 2>&1: GNU grep reports a binary-file match ("binary file X matches")
    # on stderr with nothing on stdout, so a binary file with a hit would
    # read as clean unless stderr is captured too. The -s test: a pattern
    # file may hold no unprefixed entries, and grep implementations do not
    # agree on what an empty -f file matches.
    if [ -s "$PATTERN_FILE" ]; then
        hits=$(grep -inE -f "$PATTERN_FILE" "$content" 2>&1 | head -20) || true
        if [ -n "$hits" ]; then
            printf '✗ %s: pattern hits:\n%s\n' "$label" "$hits"
            clean=1
        fi
    fi

    [ -s "$TEXT_PATTERN_FILE" ] || return $clean

    if is_binary "$content"; then
        printf '• %s: binary — every-file patterns checked, text-scoped patterns skipped\n' "$label"
        return $clean
    fi

    text_hits=$(grep -inE -f "$TEXT_PATTERN_FILE" "$content" 2>&1 | head -5) || true
    if [ -n "$text_hits" ]; then
        printf '✗ %s: text-scoped pattern hits:\n%s\n' "$label" "$text_hits"
        clean=1
    fi

    return $clean
}

# unscanned LABEL REASON records a file whose embedded metadata could not be
# read. The run carries on — every other check still reports — and then
# exits 2 instead of clean: see the end of this file.
unscanned() {
    printf '✗ %s: embedded metadata NOT scanned — %s\n' "$1" "$2"
    printf '%s\n' "$1" >> "$TMPDIR_HC/unscanned"
}

# scan_metadata NAME FILE reads FILE's embedded metadata with exiftool and
# checks the decoded fields against every loaded pattern, whatever its
# scope, reporting hits under label NAME. Returns 0 when clean or
# when the file could not be read — the second is recorded by unscanned and
# fails the run at exit, so it is never mistaken for the first.
scan_metadata() {
    mlabel="$1"
    mfile="$2"

    if ! command -v "$EXIFTOOL" >/dev/null 2>&1; then
        unscanned "$mlabel" "$EXIFTOOL not found"
        return 0
    fi

    # -a -u: duplicate and unknown tags too. -G1 -s: print each field with
    # the group it sits in, so a hit says where it was. -m: read past minor
    # format errors instead of stopping at them. --System:all drops the
    # file-system fields (name, directory, dates, permissions): they describe
    # this scan's own copy of the file, including a temp directory path that
    # is no part of the content. stderr is kept out of the scan for the same
    # reason — exiftool's complaints quote the path.
    "$EXIFTOOL" -a -u -G1 -s -m --System:all "$mfile" \
        > "$TMPDIR_HC/meta" 2> "$TMPDIR_HC/meta-err" < /dev/null

    # exiftool prints ExifToolVersion for every file it opens, including one
    # it does not recognise ("Unknown file type" arrives as a field beside
    # it; that file's bytes are still covered by scan_stream). Its absence
    # means the file was never read. The exit status cannot tell these apart:
    # an unrecognised format and a file exiftool failed to open both exit 1.
    if ! grep -q 'ExifToolVersion' "$TMPDIR_HC/meta"; then
        unscanned "$mlabel" "$EXIFTOOL did not read it: $(head -3 "$TMPDIR_HC/meta-err" | tr '\n' ' ')"
        return 0
    fi

    mhits=$(grep -inE -f "$META_PATTERN_FILE" "$TMPDIR_HC/meta" 2>&1 | head -20) || true
    if [ -n "$mhits" ]; then
        printf '✗ %s: pattern hits in embedded metadata:\n%s\n' "$mlabel" "$mhits"
        return 1
    fi
    return 0
}

# scan_commit_metadata COMMIT runs scan_metadata on each file COMMIT adds or
# modifies that git calls binary (numstat prints - for both counts) or that
# has_media_extension names, reading each one out of COMMIT's own tree. A
# merge is compared against each of its parents (-m), so a file is read
# whichever side brought it in. Returns 1 on a hit.
scan_commit_metadata() {
    mcommit="$1"
    mbad=0
    if ! git diff-tree -r -m --root --no-commit-id --no-renames --diff-filter=d \
            --numstat -z "$mcommit" > "$TMPDIR_HC/numstat" 2>/dev/null; then
        unscanned "commit $mcommit" "could not list the files it changes"
        return 0
    fi
    # -z so a path is never C-quoted; the NULs become newlines only for read.
    tr '\000' '\n' < "$TMPDIR_HC/numstat" > "$TMPDIR_HC/changed"
    tab=$(printf '\t')
    while IFS="$tab" read -r madded _mdeleted mpath; do
        [ -n "$mpath" ] || continue
        [ "$madded" = - ] || has_media_extension "$mpath" || continue
        # exiftool guesses the format from the extension before the content,
        # so the copy keeps it.
        case "${mpath##*/}" in
            *.*) mext=".$(printf '%s' "${mpath##*.}" | tr -cd 'A-Za-z0-9')" ;;
            *)   mext="" ;;
        esac
        mblob="$TMPDIR_HC/blob$mext"
        if ! git cat-file blob "$mcommit:$mpath" > "$mblob" 2>/dev/null < /dev/null; then
            unscanned "commit $mcommit: $mpath" "could not read it from the commit"
            continue
        fi
        scan_metadata "commit $mcommit: $mpath" "$mblob" || mbad=1
        rm -f "$mblob"
    done < "$TMPDIR_HC/changed"
    return $mbad
}

# scan_commits scans each commit (metadata: author, committer, full message;
# content: full patch; the embedded metadata of every binary or media file it
# adds or changes) named on stdin, one hash per line. It usually runs on the
# downstream side of a pipe — a subshell — so a hit is recorded through a
# marker file in $TMPDIR_HC, not a variable, which the parent checks at exit.
scan_commits() {
    total=0 bad=0
    while IFS= read -r c; do
        [ -n "$c" ] || continue
        total=$((total + 1))
        git show --format='AUTHOR:%an <%ae>%nCOMMITTER:%cn <%ce>%nMSG:%B' "$c" > "$TMPDIR_HC/commit" 2>/dev/null || continue
        hit=0
        scan_stream "commit $c" "$TMPDIR_HC/commit" || hit=1
        scan_commit_metadata "$c" || hit=1
        if [ "$hit" = 1 ]; then
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
        # ./ so a tracked name that starts with - is not read as an option.
        if is_binary "$f" || has_media_extension "$f"; then
            scan_metadata "file $f" "./$f" || : > "$TMPDIR_HC/dirty"
        fi
    done
    # Clean means every check ran. A file whose metadata went unread is not
    # clean, whatever the other checks found.
    [ -e "$TMPDIR_HC/dirty" ] || [ -e "$TMPDIR_HC/unscanned" ] || printf 'working tree clean\n'
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
    if ! command -v "$EXIFTOOL" >/dev/null 2>&1; then
        warn "note: $EXIFTOOL not found — the hook will refuse any push that adds or changes a binary, image or document file until it is installed"
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
        --require-private) ;;   # see Usage: the pattern file is always required
        --range)           MODE=range ;;
        *)
            if [ "$MODE" = range ] && [ -z "$RANGE" ]; then RANGE="$arg"
            else warn "unknown argument: $arg"; exit 2; fi ;;
    esac
done
[ -n "$MODE" ] || { warn "usage: $0 --all | --range A..B | --tree | --pre-push | --install-hook"; exit 2; }

[ "$MODE" = install ] && install_hook

TMPDIR_HC=$(mktemp -d)
trap 'rm -rf "$TMPDIR_HC"' EXIT
PATTERN_FILE="$TMPDIR_HC/patterns"
TEXT_PATTERN_FILE="$TMPDIR_HC/patterns-text"
META_ONLY_PATTERN_FILE="$TMPDIR_HC/patterns-meta-only"
combined_pattern_file "$PATTERN_FILE" "$TEXT_PATTERN_FILE" "$META_ONLY_PATTERN_FILE"

# Embedded metadata is decoded text, so it gets every pattern, whatever its
# scope. None of the three files holds a blank line (see
# combined_pattern_file), and together they hold at least one pattern.
META_PATTERN_FILE="$TMPDIR_HC/patterns-meta"
cat "$PATTERN_FILE" "$TEXT_PATTERN_FILE" "$META_ONLY_PATTERN_FILE" > "$META_PATTERN_FILE"

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

# A file whose embedded metadata went unread outranks a hit: the scan is
# incomplete, so nothing it printed can be read as the whole answer.
if [ -e "$TMPDIR_HC/unscanned" ]; then
    warn "$(count_lines "$TMPDIR_HC/unscanned") file(s) needed an embedded-metadata scan that did not run — refusing to report clean. Install exiftool (apt-get install libimage-exiftool-perl / brew install exiftool) or set CONSTLE_HYGIENE_EXIFTOOL."
    STATUS=2
fi

if [ "$STATUS" != 0 ]; then
    printf '\nhygiene-check FAILED — do not push until the hits above are resolved\n' >&2
fi
exit "$STATUS"
