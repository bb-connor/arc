#!/usr/bin/env bash
# check-trj4-no-implementation-backed.sh
#
# Registry/formal status gate. `implementation_backed` is not an accepted
# theorem status. This gate fails closed if the literal string
# `implementation_backed` appears anywhere under spec/registries/ or formal/,
# which would silently promote a theorem past the Evidence Gate.
#
# Exit codes:
#   0 - no occurrences (gate green)
#   1 - one or more occurrences (gate red)
#   2 - missing scan root or scan failure

set -euo pipefail

cd "$(dirname "$0")/.."

needle='implementation_backed'
roots=(spec/registries formal)

for root in "${roots[@]}"; do
  if [ ! -d "$root" ]; then
    echo "::error::registry status gate: required scan root missing: $root" >&2
    exit 2
  fi
done

hits=""
for root in "${roots[@]}"; do
  status=0
  found=$(grep -RInF -- "$needle" "$root" 2>/dev/null) || status=$?
  if [ "$status" -gt 1 ]; then
    echo "::error::registry status gate: cannot scan $root" >&2
    exit 2
  fi
  if [ -n "$found" ]; then
    hits+="${found}"$'\n'
  fi
done

if [ -n "$hits" ]; then
  echo "::error::registry status gate: found '${needle}' in tracked registry/formal sources." 1>&2
  echo "Demote these entries to 'proposed' (or 'proven'/'assumed') before merging:" 1>&2
  printf '%s' "$hits" 1>&2
  exit 1
fi

echo "registry status gate: no '${needle}' occurrences under ${roots[*]}"
