#!/usr/bin/env bash
# kani-changed-harnesses.sh
#
# Compute the set of public Kani harnesses that the current PR diff has
# touched, intersected with the `lanes.pr` lane in
# formal/rust-verification/kani-public-harnesses.toml. The output is one
# harness name per line, suitable for piping to
# `xargs -n1 cargo kani -p chio-kernel-core --lib --harness ...`.
#
# Tracking ticket: M03.P2.T7. The full PR sweep that T6 introduced is
# preserved on `main` and nightly; this script is the PR-only narrowing.
#
# Fallback contract (load-bearing): if the diff base cannot be resolved
# (shallow CI clone, detached HEAD, missing remote, ...) or if any file
# outside `crates/chio-kernel-core/src/kani_public_harnesses.rs` that the
# harnesses transitively depend on has changed, the script falls back to
# emitting every harness in `lanes.pr`. Silently producing an empty set
# in those situations would weaken the PR signal.
#
# Flags:
#   --dry-run   Print the harnesses that would run (one per line) and
#               exit 0. Empty output is success: nothing changed, so the
#               PR Kani job would skip the sweep. The CI job is
#               responsible for treating "no harnesses to run" as a pass.
#
# Environment overrides:
#   KANI_DIFF_BASE   git ref / SHA to diff against. Defaults to the merge
#                    base of HEAD with `origin/main`, then to
#                    `origin/main`, then triggers the fallback.
#
# Portability: written for bash >= 3.2 (system bash on macOS) so the
# local gate (`bash scripts/kani-changed-harnesses.sh --dry-run`) runs on
# developer laptops as well as on the ubuntu-latest CI runner.

set -euo pipefail

cd "$(dirname "$0")/.."

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run)
      DRY_RUN=1
      ;;
    -h|--help)
      sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "kani-changed-harnesses.sh: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

MANIFEST="formal/rust-verification/kani-public-harnesses.toml"
HARNESS_SOURCE="crates/chio-kernel-core/src/kani_public_harnesses.rs"

if [[ ! -f "$MANIFEST" ]]; then
  echo "kani-changed-harnesses.sh: missing $MANIFEST" >&2
  exit 1
fi
if [[ ! -f "$HARNESS_SOURCE" ]]; then
  echo "kani-changed-harnesses.sh: missing $HARNESS_SOURCE" >&2
  exit 1
fi

# 1. Load lanes.pr (newline-delimited string) from the manifest.
LANE_PR=$(python3 - "$MANIFEST" <<'PY'
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

manifest = Path(sys.argv[1])
data = tomllib.loads(manifest.read_text(encoding="utf-8"))
lane = data.get("lanes", {}).get("pr", {})
for h in lane.get("harnesses", []):
    print(h)
PY
)

if [[ -z "$LANE_PR" ]]; then
  echo "kani-changed-harnesses.sh: lanes.pr is empty in $MANIFEST" >&2
  exit 1
fi

emit_full_lane() {
  local reason="${1:-unspecified}"
  echo "kani-changed-harnesses.sh: falling back to full lanes.pr sweep ($reason)" >&2
  printf '%s\n' "$LANE_PR"
}

# 2. Determine the diff base. Fallback whenever it cannot be resolved.
BASE_REF="${KANI_DIFF_BASE:-}"
if [[ -z "$BASE_REF" ]]; then
  if git rev-parse --verify origin/main >/dev/null 2>&1; then
    if MB=$(git merge-base HEAD origin/main 2>/dev/null) && [[ -n "$MB" ]]; then
      BASE_REF="$MB"
    else
      BASE_REF="origin/main"
    fi
  fi
fi

if [[ -z "$BASE_REF" ]] || ! git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
  emit_full_lane "diff base unavailable (KANI_DIFF_BASE='${KANI_DIFF_BASE:-}', origin/main not present, likely shallow clone)"
  exit 0
fi

# 3. Compute the changed file set. If `git diff` itself fails (shallow
# history, missing object, ...) widen to the full lane.
if ! CHANGED_FILES=$(git diff --name-only "$BASE_REF"...HEAD 2>/dev/null); then
  emit_full_lane "git diff against '$BASE_REF' failed"
  exit 0
fi

if [[ -z "$CHANGED_FILES" ]]; then
  # Clean tree relative to base: nothing to verify on the PR lane.
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "kani-changed-harnesses.sh: no files changed vs $BASE_REF; nothing to run" >&2
  fi
  exit 0
fi

# 4. Any change outside the harness source file but inside crates the
# harnesses link against (chio-kernel-core, chio-core-types) or to the
# manifest itself widens the lane back to the full sweep. The harnesses
# witness public symbols in those crates, so a change there can flip a
# proof without altering the harness source line itself; emitting an
# empty set in that case would silently weaken the PR signal.
WIDEN=0
WIDEN_REASON=""
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  case "$f" in
    "$HARNESS_SOURCE")
      ;;
    "$MANIFEST")
      WIDEN=1
      WIDEN_REASON="manifest changed ($f)"
      break
      ;;
    crates/chio-kernel-core/*|crates/chio-core-types/*)
      WIDEN=1
      WIDEN_REASON="proof-relevant crate file changed ($f)"
      break
      ;;
  esac
done <<< "$CHANGED_FILES"

if [[ "$WIDEN" -eq 1 ]]; then
  emit_full_lane "$WIDEN_REASON"
  exit 0
fi

# 5. The harness source file is the only proof-relevant change (or it
# was not touched at all). Compute per-harness line ranges and intersect
# with `git diff -U0` hunk lines.
if ! printf '%s\n' "$CHANGED_FILES" | grep -qx "$HARNESS_SOURCE"; then
  # Harness source is untouched and nothing in steps 1-4 widened the
  # lane; emit the empty set.
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "kani-changed-harnesses.sh: no proof-relevant files changed vs $BASE_REF" >&2
  fi
  exit 0
fi

# Collect changed line numbers in the harness source on the new side.
CHANGED_LINES_RAW=$(git diff -U0 "$BASE_REF"...HEAD -- "$HARNESS_SOURCE" 2>/dev/null || true)
if [[ -z "$CHANGED_LINES_RAW" ]]; then
  # Shouldn't happen if the file is in CHANGED_FILES, but be safe.
  emit_full_lane "could not compute hunk lines for $HARNESS_SOURCE"
  exit 0
fi

PARSE_HUNKS_PY=$(cat <<'PY'
import re
import sys

# Parse `@@ -a,b +c,d @@` hunk headers and emit each touched new-side
# line number. `+c` with no `,d` means a single line. `+c,0` means a
# pure deletion (no new-side lines); skip it.
hunk = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@')
for line in sys.stdin:
    m = hunk.match(line)
    if not m:
        continue
    start = int(m.group(1))
    count = int(m.group(2)) if m.group(2) is not None else 1
    if count == 0:
        continue
    for n in range(start, start + count):
        print(n)
PY
)
CHANGED_LINES=$(printf '%s\n' "$CHANGED_LINES_RAW" | python3 -c "$PARSE_HUNKS_PY")

if [[ -z "$CHANGED_LINES" ]]; then
  # Pure deletion in the harness source; treat as no functional change.
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "kani-changed-harnesses.sh: only deletions in $HARNESS_SOURCE; nothing to run" >&2
  fi
  exit 0
fi

# 6. Intersect the changed line set with each harness function's range.
# Any change in the harness source that falls *outside* a harness range
# (imports, shared helpers, the prelude before the first #[kani::proof])
# widens the lane back to the full sweep, since any of the public
# harnesses could depend on the touched helper.
RANGE_INTERSECT_PY=$(cat <<'PY'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()

# Find every `#[kani::proof]` attribute and the `fn <name>` that follows.
# The function's range is from the `#[kani::proof]` line through the
# line before the next `#[kani::proof]` (or EOF). This is a coarse upper
# bound that is conservative on purpose: it captures the function body
# plus any trailing whitespace or comments that belong to that harness.
proof = re.compile(r'^\s*#\[kani::proof\]')
fn_re = re.compile(r'^\s*(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)')

starts = []
for idx, line in enumerate(source, start=1):
    if proof.match(line):
        starts.append(idx)

ranges = []  # (name, start_line, end_line)
for i, start in enumerate(starts):
    end = starts[i + 1] - 1 if i + 1 < len(starts) else len(source)
    name = None
    for j in range(start, end + 1):
        m = fn_re.match(source[j - 1])
        if m:
            name = m.group(1)
            break
    if name is not None:
        ranges.append((name, start, end))

changed = set()
for tok in sys.stdin.read().split():
    try:
        changed.add(int(tok))
    except ValueError:
        pass

hits = []
outside = False
for ln in sorted(changed):
    in_range = False
    for name, start, end in ranges:
        if start <= ln <= end:
            in_range = True
            if name not in hits:
                hits.append(name)
            break
    if not in_range:
        outside = True
        break

if outside:
    print("WIDEN")
else:
    for name in hits:
        print(name)
PY
)
ANALYSIS=$(printf '%s\n' "$CHANGED_LINES" | python3 -c "$RANGE_INTERSECT_PY" "$HARNESS_SOURCE")

if printf '%s\n' "$ANALYSIS" | grep -qx "WIDEN"; then
  emit_full_lane "harness source change outside any #[kani::proof] range (imports/helpers touched)"
  exit 0
fi

CHANGED_HARNESSES=$(printf '%s\n' "$ANALYSIS" | grep -v '^$' || true)

# 7. Intersect changed harnesses with lanes.pr and emit. Order is
# preserved as it appears in lanes.pr so the CI run order is stable.
if [[ -z "$CHANGED_HARNESSES" ]]; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "kani-changed-harnesses.sh: harness diff produced no harness names" >&2
  fi
  exit 0
fi

EMITTED=0
while IFS= read -r lane_h; do
  [[ -z "$lane_h" ]] && continue
  if printf '%s\n' "$CHANGED_HARNESSES" | grep -qx "$lane_h"; then
    printf '%s\n' "$lane_h"
    EMITTED=$((EMITTED + 1))
  fi
done <<< "$LANE_PR"

if [[ "$DRY_RUN" -eq 1 && "$EMITTED" -eq 0 ]]; then
  echo "kani-changed-harnesses.sh: no lanes.pr harnesses intersect the diff" >&2
fi

exit 0
