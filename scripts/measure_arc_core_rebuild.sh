#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

PACKAGE="${ARC_REBUILD_PACKAGE:-hello-tool}"
BASELINE_TOUCH="${ARC_REBUILD_BASELINE_TOUCH:-crates/arc-core/src/capability.rs}"
SPLIT_TOUCH="${ARC_REBUILD_SPLIT_TOUCH:-crates/arc-core-types/src/capability.rs}"
SPLIT_REF="${ARC_REBUILD_SPLIT_REF:-HEAD}"

FIRST_SPLIT_COMMIT=$(
    git -C "$REPO_ROOT" log \
        --format='%H' \
        --grep='^feat(303-01): create shared arc core types crate$' \
        -n 1
)

if [[ -z "$FIRST_SPLIT_COMMIT" ]]; then
    echo "could not locate the first phase-303 split commit" >&2
    exit 1
fi

BASELINE_REF="${ARC_REBUILD_BASELINE_REF:-${FIRST_SPLIT_COMMIT}^}"

TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/arc-core-rebuild.XXXXXX")
BASELINE_DIR="$TMP_ROOT/baseline"
SPLIT_DIR="$TMP_ROOT/split"

cleanup() {
    git -C "$REPO_ROOT" worktree remove --force "$BASELINE_DIR" >/dev/null 2>&1 || true
    git -C "$REPO_ROOT" worktree remove --force "$SPLIT_DIR" >/dev/null 2>&1 || true
    rm -rf "$TMP_ROOT"
}

trap cleanup EXIT

git -C "$REPO_ROOT" worktree add --quiet --detach "$BASELINE_DIR" "$BASELINE_REF"
git -C "$REPO_ROOT" worktree add --quiet --detach "$SPLIT_DIR" "$SPLIT_REF"

measure_case() {
    local label="$1"
    local worktree="$2"
    local touch_file="$3"
    local target_dir="$4"
    local log_file="$TMP_ROOT/${label}.log"

    echo "== ${label} ==" >&2
    echo "ref: $(git -C "$worktree" rev-parse --short HEAD)" >&2
    echo "package: $PACKAGE" >&2
    echo "touch: $touch_file" >&2

    (
        cd "$worktree"
        export CARGO_TARGET_DIR="$target_dir"
        cargo check -q -p "$PACKAGE" >/dev/null
        touch "$touch_file"
        /usr/bin/time -p cargo check -q -p "$PACKAGE"
    ) 2>&1 | tee "$log_file" >&2

    awk '/^real / {print $2}' "$log_file" | tail -n 1
}

BASELINE_REAL=$(measure_case baseline "$BASELINE_DIR" "$BASELINE_TOUCH" "$TMP_ROOT/target-baseline")
SPLIT_REAL=$(measure_case split "$SPLIT_DIR" "$SPLIT_TOUCH" "$TMP_ROOT/target-split")

echo
echo "== comparison =="
printf 'baseline_real_seconds=%s\n' "$BASELINE_REAL"
printf 'split_real_seconds=%s\n' "$SPLIT_REAL"
awk -v baseline_time="$BASELINE_REAL" -v split_time="$SPLIT_REAL" '
    BEGIN {
        if (split_time <= 0) {
            print "split timing was not positive" > "/dev/stderr";
            exit 1;
        }
        printf "speedup_ratio=%.2fx\n", baseline_time / split_time;
        printf "delta_seconds=%.2f\n", baseline_time - split_time;
    }
'
