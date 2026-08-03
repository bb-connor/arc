#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=1
export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }--cfg chio_kernel_loom"

EXPECTED_TESTS=(
  protocol_primitives_last_unit_contention
  protocol_primitives_three_key_all_or_nothing
  protocol_primitives_immutable_maximum_race
  protocol_primitives_capture_versus_reverse
  protocol_primitives_idempotent_compensation
)

list_output="$(mktemp "${TMPDIR:-/tmp}/chio-protocol-primitives-loom-list.XXXXXX")"
run_output="$(mktemp "${TMPDIR:-/tmp}/chio-protocol-primitives-loom-run.XXXXXX")"
trap 'rm -f "${list_output}" "${run_output}"' EXIT

set +e
cargo test -p chio-kernel --features loom-tests --test loom_concurrency protocol_primitives_ -- --list 2>&1 | tee "${list_output}"
list_status=${PIPESTATUS[0]}
set -e

if [[ "${list_status}" -ne 0 ]]; then
  exit "${list_status}"
fi

python3 - "${list_output}" "${EXPECTED_TESTS[@]}" <<'PY'
import re
import sys
from pathlib import Path

ansi_escape = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
observed = []
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    clean = ansi_escape.sub("", line).strip()
    match = re.fullmatch(r"([A-Za-z0-9_:]+): test", clean)
    if match:
        observed.append(match.group(1))

expected = sys.argv[2:]
if len(observed) != len(set(observed)):
    raise SystemExit(
        "protocol-primitives Loom gate listed duplicate tests: "
        f"{sorted(observed)!r}"
    )
if set(observed) != set(expected):
    missing = sorted(set(expected) - set(observed))
    unexpected = sorted(set(observed) - set(expected))
    raise SystemExit(
        "protocol-primitives Loom gate exact test set mismatch: "
        f"missing={missing!r} unexpected={unexpected!r}"
    )
PY

set +e
cargo test -p chio-kernel --features loom-tests --test loom_concurrency protocol_primitives_ 2>&1 | tee "${run_output}"
status=${PIPESTATUS[0]}
set -e

if [[ "${status}" -ne 0 ]]; then
  exit "${status}"
fi

python3 - "${run_output}" "${EXPECTED_TESTS[@]}" <<'PY'
import re
import sys
from pathlib import Path

ansi_escape = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
lines = [
    ansi_escape.sub("", line).strip()
    for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
]
expected = sys.argv[2:]
observed = []
for line in lines:
    match = re.fullmatch(r"test ([A-Za-z0-9_:]+) \.\.\. ok", line)
    if match:
        observed.append(match.group(1))

if len(observed) != len(set(observed)) or set(observed) != set(expected):
    missing = sorted(set(expected) - set(observed))
    unexpected = sorted(set(observed) - set(expected))
    raise SystemExit(
        "protocol-primitives Loom execution set mismatch: "
        f"missing={missing!r} unexpected={unexpected!r} observed={observed!r}"
    )

summary = re.compile(
    rf"test result: ok\. {len(expected)} passed; 0 failed; 0 ignored; "
    r"0 measured; [0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s"
)
matching_summaries = [line for line in lines if summary.fullmatch(line)]
if len(matching_summaries) != 1:
    raise SystemExit(
        "protocol-primitives Loom execution summary is absent, non-exact, or ambiguous; "
        f"expected exactly {len(expected)} passed with zero failed, ignored, or measured tests"
    )
PY

echo "Protocol-primitives Loom gate passed (${#EXPECTED_TESTS[@]} exact tests)"
