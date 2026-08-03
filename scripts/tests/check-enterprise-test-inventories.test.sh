#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-enterprise-test-inventories.sh"
test -x "${runner}"
bash -n "${runner}"
grep -Fq './scripts/check-enterprise-cross-mechanism.sh' "${runner}"

python3 - "${runner}" <<'PY'
import re
import shlex
import sys
from pathlib import Path


TEST_PATTERN = re.compile(
    r"#\[(?:tokio::)?test(?:\([^]]*\))?\]\s*"
    r"(?:#\[[^]]+\]\s*)*(?:async\s+)?fn\s+([A-Za-z0-9_]+)"
)
GO_TEST_PATTERN = re.compile(r"(?m)^func\s+(Test[A-Za-z0-9_]+)\s*\(")


def parse_calls(path: Path) -> dict[str, tuple[list[str], list[str]]]:
    logical = path.read_text(encoding="utf-8").replace("\\\n", " ")
    calls = {}
    cargo_test_lines = 0
    for raw in logical.splitlines():
        line = raw.strip()
        if "cargo test" in line:
            cargo_test_lines += 1
        if not line.startswith("./scripts/run-exact-cargo-test-inventory.sh "):
            continue
        tokens = shlex.split(line)
        label = tokens[tokens.index("--label") + 1]
        expected_start = tokens.index("--expected") + 1
        separator = tokens.index("--")
        expected = tokens[expected_start:separator]
        command = tokens[separator + 1 :]
        if not expected or len(expected) != len(set(expected)):
            raise SystemExit(f"{label}: empty or duplicate enterprise inventory")
        if command[:2] != ["cargo", "test"]:
            raise SystemExit(f"{label}: inventory does not own a Cargo test command")
        calls[label] = (expected, command)
    if cargo_test_lines != len(calls):
        raise SystemExit(
            "enterprise Cargo tests must all be owned by exact inventory calls: "
            f"commands={cargo_test_lines} calls={len(calls)}"
        )
    return calls


calls = parse_calls(Path(sys.argv[1]))
expected_commands = {
    "enterprise migration state": [
        "cargo", "test", "-p", "chio-store-sqlite", "--test", "enterprise_migration_state"
    ],
    "threat-model schema": [
        "cargo", "test", "-p", "chio-spec-codegen", "--test", "threat_model_schema_test"
    ],
    "Rust generated security vectors": [
        "cargo", "test", "-p", "chio-core-types", "--test", "security_generated_vectors"
    ],
    "threat-model conformance": [
        "cargo", "test", "-p", "chio-conformance", "--test", "threats"
    ],
}
observed_commands = {label: command for label, (_, command) in calls.items()}
if observed_commands != expected_commands:
    raise SystemExit(
        "enterprise target command inventory mismatch: "
        f"expected={expected_commands!r} observed={observed_commands!r}"
    )

migration = TEST_PATTERN.findall(
    Path("crates/platform/chio-store-sqlite/tests/enterprise_migration_state.rs")
    .read_text(encoding="utf-8")
)
schema = TEST_PATTERN.findall(
    Path("crates/tooling/chio-spec-codegen/tests/threat_model_schema_test.rs")
    .read_text(encoding="utf-8")
)
rust_security_vectors = TEST_PATTERN.findall(
    Path("crates/core/chio-core-types/tests/security_generated_vectors.rs")
    .read_text(encoding="utf-8")
)
threat_root = Path("crates/tooling/chio-conformance/tests/threats.rs").read_text(
    encoding="utf-8"
)
threats = []
for relative, module in re.findall(
    r'#\[path = "(threats/[A-Za-z0-9_]+\.rs)"\]\s*mod ([A-Za-z0-9_]+);',
    threat_root,
):
    raw = Path("crates/tooling/chio-conformance/tests", relative).read_text(
        encoding="utf-8"
    )
    threats.extend(f"{module}::{name}" for name in TEST_PATTERN.findall(raw))

expected_sources = {
    "enterprise migration state": migration,
    "threat-model schema": schema,
    "Rust generated security vectors": rust_security_vectors,
    "threat-model conformance": threats,
}
for label, expected in expected_sources.items():
    observed = calls[label][0]
    if sorted(observed) != sorted(expected):
        raise SystemExit(
            f"{label}: committed inventory differs from source: "
            f"missing={sorted(set(expected) - set(observed))!r} "
            f"unexpected={sorted(set(observed) - set(expected))!r}"
        )

counts = {label: len(expected) for label, (expected, _) in calls.items()}
if counts != {
    "enterprise migration state": 12,
    "threat-model schema": 7,
    "Rust generated security vectors": 10,
    "threat-model conformance": 49,
}:
    raise SystemExit(f"enterprise exact target counts changed: {counts!r}")

runner_body = Path(sys.argv[1]).read_text(encoding="utf-8")
go_array = re.search(
    r"(?ms)^go_security_vector_tests=\(\n(?P<body>.*?)^\)\n",
    runner_body,
)
if go_array is None:
    raise SystemExit("Go generated security vector inventory is missing")
go_expected = shlex.split(go_array.group("body"))
if not go_expected or len(go_expected) != len(set(go_expected)):
    raise SystemExit("Go generated security vector inventory is empty or duplicated")
if go_expected != sorted(go_expected):
    raise SystemExit("Go generated security vector inventory is not sorted")
go_source = GO_TEST_PATTERN.findall(
    Path("sdks/go/chio-go-http/security_generated_vectors_test.go")
    .read_text(encoding="utf-8")
)
if go_expected != sorted(go_source):
    raise SystemExit(
        "Go generated security vector inventory differs from source: "
        f"missing={sorted(set(go_source) - set(go_expected))!r} "
        f"unexpected={sorted(set(go_expected) - set(go_source))!r}"
    )
if len(go_expected) != 9:
    raise SystemExit(f"Go generated security vector count changed: {len(go_expected)}")

required_go_contract = (
    "printf '^(%s)$' \"${go_security_vector_tests[*]}\"",
    "printf '%s\\n' \"${go_security_vector_tests[@]}\" | LC_ALL=C sort",
    "go test ./... -list \"${go_security_vector_pattern}\"",
    "test -n \"${actual_go_security_vectors}\"",
    "test \"${actual_go_security_vectors}\" = \"${expected_go_security_vectors}\"",
    "go test ./... -run \"${go_security_vector_pattern}\" -count=1",
)
missing_go_contract = [
    fragment for fragment in required_go_contract if fragment not in runner_body
]
if missing_go_contract or runner_body.count("cd sdks/go/chio-go-http") != 2:
    raise SystemExit(
        "Go generated security vector execution contract changed: "
        f"missing={missing_go_contract!r}"
    )
PY

echo "enterprise exact test inventory contract passed (87 tests plus composition)"
