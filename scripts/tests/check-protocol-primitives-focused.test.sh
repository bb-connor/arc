#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-protocol-primitives-focused.sh"
exact_runner="scripts/run-exact-cargo-test-inventory.sh"
test -x "${runner}"
test -x "${exact_runner}"
bash -n "${runner}" "${exact_runner}"

python3 - "${runner}" <<'PY'
import glob
import hashlib
import re
import shlex
import sys
from pathlib import Path


TEST_PATTERN = re.compile(
    r"#\[(?:tokio::)?test(?:\([^]]*\))?\]\s*"
    r"(?:#\[[^]]+\]\s*)*(?:async\s+)?fn\s+([A-Za-z0-9_]+)"
)


def parse_calls(path: Path) -> list[tuple[str, bool, int, str, list[str]]]:
    logical = path.read_text(encoding="utf-8").replace("\\\n", " ")
    calls = []
    for raw in logical.splitlines():
        line = raw.strip()
        if not line.startswith(("run_committed_inventory", "run_complete_inventory")):
            continue
        tokens = shlex.split(line)
        if not tokens or tokens[0] not in {
            "run_committed_inventory",
            "run_complete_inventory",
        }:
            continue
        if len(tokens) < 8 or tokens[4:6] != ["cargo", "test"]:
            raise SystemExit(f"malformed committed protocol inventory: {line}")
        label = tokens[1]
        count = int(tokens[2])
        digest = tokens[3]
        command = tokens[4:]
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise SystemExit(f"{label}: malformed inventory SHA-256")
        calls.append((label, tokens[0] == "run_committed_inventory", count, digest, command))
    return calls


def source_commitment(prefix: str, paths: list[str]) -> tuple[int, str]:
    names = []
    for path in paths:
        names.extend(
            prefix + name
            for name in TEST_PATTERN.findall(Path(path).read_text(encoding="utf-8"))
        )
    canonical = ("\n".join(sorted(names)) + "\n").encode("utf-8")
    return len(names), hashlib.sha256(canonical).hexdigest()


calls = parse_calls(Path(sys.argv[1]))
expected_commands = {
    "kernel budget characterization": [
        "cargo", "test", "-p", "chio-kernel", "--lib", "kernel::tests::budget::"
    ],
    "kernel approval characterization": [
        "cargo", "test", "-p", "chio-kernel", "--lib", "kernel::tests::approval_flow::"
    ],
    "kernel governed budget-chain characterization": [
        "cargo", "test", "-p", "chio-kernel", "--lib",
        "kernel::tests::budget_governed_call_chain::",
    ],
    "SQLite budget characterization": [
        "cargo", "test", "-p", "chio-store-sqlite", "--lib", "budget_store::tests::"
    ],
    "aggregate root model": [
        "cargo", "test", "-p", "chio-core-types", "--features", "fips", "--lib",
        "capability::aggregate_budget::tests::",
    ],
    "aggregate attenuation model": [
        "cargo", "test", "-p", "chio-core-types", "--lib",
        "capability::aggregate_invocation_attenuation_tests::",
    ],
    "delegation family model": [
        "cargo", "test", "-p", "chio-core-types", "--lib",
        "capability::delegation_family_tests::",
    ],
    "portable capability verification": [
        "cargo", "test", "-p", "chio-kernel-core", "--lib", "capability_verify::tests::"
    ],
    "generated security binding corpus": [
        "cargo", "test", "-p", "chio-core-types", "--test",
        "security_generated_vectors",
    ],
    "SQLite composite budget persistence": [
        "cargo", "test", "-p", "chio-store-sqlite", "--lib", "budget_store::tests::"
    ],
    "control-plane budget composition": [
        "cargo", "test", "-p", "chio-control-plane", "--lib",
        "trust_control::service_runtime::tests::budget::",
    ],
    "control-plane admission consensus": [
        "cargo", "test", "-p", "chio-control-plane", "--lib",
        "trust_control::cluster::admission_consensus::tests::",
    ],
    "protocol primitives tier 1 conformance": [
        "cargo", "test", "-p", "chio-conformance", "--test",
        "protocol_primitives_t1",
    ],
    "protocol primitives tier 2 conformance": [
        "cargo", "test", "-p", "chio-conformance", "--test",
        "protocol_primitives_t2",
    ],
}
observed_commands = {label: command for label, _, _, _, command in calls}
if observed_commands != expected_commands:
    raise SystemExit(
        "focused protocol command inventory changed: "
        f"expected={expected_commands!r} observed={observed_commands!r}"
    )

observed_filtering = {label: filtered for label, filtered, _, _, _ in calls}
expected_filtering = {label: True for label in expected_commands}
expected_filtering["protocol primitives tier 1 conformance"] = False
expected_filtering["protocol primitives tier 2 conformance"] = False
expected_filtering["generated security binding corpus"] = False
if observed_filtering != expected_filtering:
    raise SystemExit(
        "focused protocol filtering contract changed: "
        f"expected={expected_filtering!r} observed={observed_filtering!r}"
    )

source_contracts = {
    "kernel budget characterization": (
        "kernel::tests::budget::",
        sorted(glob.glob("crates/kernel/chio-kernel/src/kernel/tests/budget.part*.inc")),
    ),
    "kernel approval characterization": (
        "kernel::tests::approval_flow::",
        ["crates/kernel/chio-kernel/src/kernel/tests/approval_flow.rs"],
    ),
    "kernel governed budget-chain characterization": (
        "kernel::tests::budget_governed_call_chain::",
        ["crates/kernel/chio-kernel/src/kernel/tests/budget_governed_call_chain.rs"],
    ),
    "SQLite budget characterization": (
        "budget_store::tests::",
        sorted(glob.glob("crates/platform/chio-store-sqlite/src/budget_store/tests_parts/*.rs")),
    ),
    "aggregate root model": (
        "capability::aggregate_budget::tests::",
        sorted(glob.glob("crates/core/chio-core-types/src/capability/aggregate_budget.part*.inc")),
    ),
    "aggregate attenuation model": (
        "capability::aggregate_invocation_attenuation_tests::",
        ["crates/core/chio-core-types/src/capability/aggregate_invocation_attenuation_tests.rs"],
    ),
    "delegation family model": (
        "capability::delegation_family_tests::",
        ["crates/core/chio-core-types/src/capability/delegation_family_tests.rs"],
    ),
    "portable capability verification": (
        "capability_verify::tests::",
        ["crates/kernel/chio-kernel-core/src/capability_verify.rs"],
    ),
    "generated security binding corpus": (
        "",
        ["crates/core/chio-core-types/tests/security_generated_vectors.rs"],
    ),
    "SQLite composite budget persistence": (
        "budget_store::tests::",
        sorted(glob.glob("crates/platform/chio-store-sqlite/src/budget_store/tests_parts/*.rs")),
    ),
    "control-plane budget composition": (
        "trust_control::service_runtime::tests::budget::",
        sorted(glob.glob(
            "crates/platform/chio-control-plane/src/trust_control/"
            "service_runtime/tests/budget_parts/*.inc"
        )),
    ),
    "control-plane admission consensus": (
        "trust_control::cluster::admission_consensus::tests::",
        sorted(glob.glob(
            "crates/platform/chio-control-plane/src/trust_control/cluster/"
            "admission_consensus_parts/nested_*.inc"
        )),
    ),
    "protocol primitives tier 1 conformance": (
        "",
        ["crates/tooling/chio-conformance/tests/protocol_primitives_t1.rs"],
    ),
    "protocol primitives tier 2 conformance": (
        "",
        ["crates/tooling/chio-conformance/tests/protocol_primitives_t2.rs"],
    ),
}
observed_commitments = {
    label: (count, digest) for label, _, count, digest, _ in calls
}
expected_commitments = {
    label: source_commitment(prefix, paths)
    for label, (prefix, paths) in source_contracts.items()
}
if observed_commitments != expected_commitments:
    raise SystemExit(
        "focused protocol inventory commitment drift: "
        f"expected={expected_commitments!r} observed={observed_commitments!r}"
    )

if not all(count > 0 for count, _ in observed_commitments.values()):
    raise SystemExit("focused protocol inventory contains an empty target")

expected_exact_counts = {
    "control-plane admission consensus": 61,
    "protocol primitives tier 1 conformance": 10,
    "protocol primitives tier 2 conformance": 10,
    "generated security binding corpus": 10,
}
for label, count in expected_exact_counts.items():
    if expected_commitments[label][0] != count:
        raise SystemExit(
            f"{label}: source inventory count changed: "
            f"expected={count} observed={expected_commitments[label][0]}"
        )

admission_parts = [
    len(TEST_PATTERN.findall(Path(path).read_text(encoding="utf-8")))
    for path in source_contracts["control-plane admission consensus"][1]
]
if admission_parts != [28, 18, 15]:
    raise SystemExit(
        "control-plane admission consensus source partition changed: "
        f"expected={[28, 18, 15]!r} observed={admission_parts!r}"
    )

def inventory_commitment(names: list[str]) -> tuple[int, str]:
    canonical = ("\n".join(sorted(names)) + "\n").encode("utf-8")
    return len(names), hashlib.sha256(canonical).hexdigest()


for label in expected_exact_counts:
    prefix, paths = source_contracts[label]
    names = []
    for path in paths:
        names.extend(
            prefix + name
            for name in TEST_PATTERN.findall(Path(path).read_text(encoding="utf-8"))
        )
    mutants = {
        "missing": names[:-1],
        "extra": names + [prefix + "uncommitted_inventory_case"],
        "renamed": names[:-1] + [prefix + "renamed_inventory_case"],
        "zero": [],
    }
    for mutation, mutant in mutants.items():
        if inventory_commitment(mutant) == observed_commitments[label]:
            raise SystemExit(f"{label}: {mutation} inventory mutation was accepted")
PY

for required in \
  './scripts/run-exact-cargo-test-inventory.sh' \
  '--allow-filtered' \
  '--expected-count' \
  '--expected-sha256'
do
  grep -Fq -- "${required}" "${runner}"
done

python3 scripts/tests/check-exact-cargo-test-inventory.test.py

if rg -n '^cargo test -p chio-(kernel|store-sqlite|core-types|kernel-core|control-plane) (budget|approval|budget_store|aggregate_invocation|delegation)$' \
  docs/superpowers/plans/2026-07-09-protocol-primitives.md; then
  echo "protocol plan still contains a raw zero-match-prone phase command" >&2
  exit 1
fi
for lane in baseline model persistence; do
  if ! grep -Fq "./scripts/check-protocol-primitives-focused.sh --${lane}" \
    docs/superpowers/plans/2026-07-09-protocol-primitives.md; then
    echo "protocol plan omits the ${lane} focused ratchet" >&2
    exit 1
  fi
done

grep -Fq 'python3 scripts/check-protocol-primitives-vectors.py' "${runner}"

echo "protocol-primitives focused gate self-test passed (14 committed inventories)"
