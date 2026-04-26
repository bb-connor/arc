#!/usr/bin/env bash
# scripts/check-regression-tests.sh
#
# Regression-test deletion guard (M02.P4.T3).
#
# Detects deletion of fuzz-promoted regression tests under either
# tests/regression_*.rs (legacy layout) or crates/*/tests/regression_*.rs
# (current layout, written by scripts/promote_fuzz_seed.sh in T2).
# Fails CI when any such file disappears between BASE..HEAD without a
# paired issue link in the PR body or merge commit message.
#
# Mechanism:
#   1. git diff --diff-filter=D --name-only $BASE..$HEAD
#   2. filter for tests/regression_*.rs or crates/*/tests/regression_*.rs
#   3. for each deleted file, look for a paired issue link in:
#        - the GitHub PR body (PR_BODY env var, set by ci.yml step)
#        - the range of commit messages between BASE and HEAD
#      A "paired issue link" is one of:
#        - "closes #N", "fixes #N", "resolves #N", "tracks #N"  (any case)
#        - a URL to a github.com issue or PR
#   4. exit 0 if no deletions OR every deletion is paired; exit 1 otherwise.
#
# Usage:
#   check-regression-tests.sh [--dry-run] [--base REF] [--head REF] [--help]
#
# Args:
#   --dry-run    no-op self-test, exit 0 (used by gate_check)
#   --base REF   base ref (default: origin/main, or $GITHUB_BASE_REF)
#   --head REF   head ref (default: HEAD)
#   --help       show this help and exit 0
#
# Source-doc anchor:
#   .planning/trajectory/02-fuzzing-post-pr13.md
#     Phase 4 P4.T3 + Crash-triage automation > CODEOWNERS gate paragraph

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: check-regression-tests.sh [--dry-run] [--base REF] [--head REF] [--help]

Regression-test deletion guard. Fails CI when a regression_*.rs file is
deleted between BASE..HEAD without a paired issue link in the PR body
or commit messages.

Args:
  --dry-run    no-op self-test, exit 0
  --base REF   base ref (default: origin/main or $GITHUB_BASE_REF)
  --head REF   head ref (default: HEAD)
  --help       show this help

Env:
  PR_BODY        GitHub PR body, used to look for paired issue links
  GITHUB_BASE_REF  fallback for --base when running under actions/checkout

Exit codes:
  0  no deletions, or every deletion paired with an issue link
  1  unpaired deletion detected
  2  invocation error
EOF
}

DRY_RUN=0
BASE=""
HEAD_REF="HEAD"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --base)
            if [[ $# -lt 2 ]]; then
                echo "check-regression-tests: --base requires an argument" >&2
                exit 2
            fi
            BASE="$2"
            shift 2
            ;;
        --head)
            if [[ $# -lt 2 ]]; then
                echo "check-regression-tests: --head requires an argument" >&2
                exit 2
            fi
            HEAD_REF="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "check-regression-tests: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "check-regression-tests: dry-run OK"
    exit 0
fi

# Resolve BASE if not given.
if [[ -z "$BASE" ]]; then
    if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
        BASE="origin/${GITHUB_BASE_REF}"
    else
        BASE="origin/main"
    fi
fi

# Sanity-check refs exist.
if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
    echo "check-regression-tests: base ref '$BASE' not found" >&2
    exit 2
fi
if ! git rev-parse --verify --quiet "$HEAD_REF" >/dev/null; then
    echo "check-regression-tests: head ref '$HEAD_REF' not found" >&2
    exit 2
fi

# Collect deleted files between BASE..HEAD that match regression-test paths.
DELETED=$(git diff --diff-filter=D --name-only "$BASE..$HEAD_REF" \
    | grep -E '(^tests/regression_[^/]+\.rs$|^crates/[^/]+/tests/regression_[^/]+\.rs$)' \
    || true)

if [[ -z "$DELETED" ]]; then
    echo "check-regression-tests: no regression-test deletions in $BASE..$HEAD_REF; OK"
    exit 0
fi

# Gather text to search for issue links: PR body + commit message range.
SEARCH_TEXT=""
if [[ -n "${PR_BODY:-}" ]]; then
    SEARCH_TEXT+="${PR_BODY}"$'\n'
fi
SEARCH_TEXT+="$(git log --format='%B' "$BASE..$HEAD_REF" 2>/dev/null || true)"

# Pairing regex:
#   - closes/fixes/resolves/tracks/refs #N
#   - github.com/<org>/<repo>/issues/N or /pull/N URL
PAIR_REGEX='(closes|fixes|resolves|tracks|refs)[[:space:]]+#[0-9]+|https?://github\.com/[^/[:space:]]+/[^/[:space:]]+/(issues|pull)/[0-9]+'

unpaired=0
echo "check-regression-tests: deleted regression tests detected; checking for paired issue links"
while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    if echo "$SEARCH_TEXT" | grep -iqE "$PAIR_REGEX"; then
        echo "  PAIRED   $path"
    else
        echo "  UNPAIRED $path" >&2
        unpaired=$((unpaired + 1))
    fi
done <<< "$DELETED"

if [[ "$unpaired" -gt 0 ]]; then
    cat >&2 <<EOF

check-regression-tests: $unpaired regression test(s) deleted without a
paired issue link. Add one of the following to the PR body or a commit
message in this branch and re-run:

  closes #<n>            (or fixes / resolves / tracks / refs)
  https://github.com/<org>/<repo>/issues/<n>

Each deleted regression_*.rs corresponds to a fuzz-found crash. Removing
it without filing a follow-up issue silently regresses crash coverage.
EOF
    exit 1
fi

echo "check-regression-tests: all deletions paired; OK"
exit 0
