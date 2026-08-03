#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-deception-security.sh"
exact_runner="scripts/run-exact-cargo-test-inventory.sh"
verifier="scripts/check-exact-cargo-test-inventory.py"
test -x "${runner}"
test -x "${exact_runner}"
test -x "${verifier}"
bash -n "${runner}" "${exact_runner}"

validate_runner() {
  python3 - "$1" <<'PY'
import re
import shlex
import sys
from pathlib import Path


ROOT = Path.cwd()


def rust_tests(relative_path: str) -> list[str]:
    source = (ROOT / relative_path).read_text(encoding="utf-8")
    return re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source)


def rust_tests_with_exact_includes(
    relative_path: str, expected_includes: set[str]
) -> list[str]:
    entrypoint = ROOT / relative_path
    source = entrypoint.read_text(encoding="utf-8")
    includes = set(
        re.findall(r'(?m)^\s*include!\("([^"]+\.rs)"\);\s*$', source)
    )
    if includes != expected_includes:
        raise SystemExit(
            f"{relative_path}: included Rust sources changed: {sorted(includes)!r}"
        )
    fragment_root = entrypoint.parent / entrypoint.stem
    fragments = {
        path.relative_to(entrypoint.parent) for path in fragment_root.rglob("*.rs")
    }
    expected_fragments = {Path(include) for include in expected_includes}
    if fragments != expected_fragments:
        raise SystemExit(
            f"{relative_path}: Rust source fragments changed: "
            f"observed={sorted(map(str, fragments))!r} "
            f"expected={sorted(map(str, expected_fragments))!r}"
        )
    tests = rust_tests(relative_path)
    for include in sorted(includes):
        tests.extend(rust_tests(str(entrypoint.parent.joinpath(include).relative_to(ROOT))))
    return tests


materialize = rust_tests("crates/security/chio-decoy/tests/materialize.rs")
materialize.remove("non_unix_materializer_is_explicitly_unsupported")
adapters = rust_tests("crates/security/chio-security-kernel/tests/adapters.rs")
active_defense = rust_tests_with_exact_includes(
    "crates/tooling/chio-conformance/tests/active_defense.rs",
    {
        "active_defense/deception_dispatch.rs",
        "active_defense/partial_rollback.rs",
    },
)

expected = {
    "decoy coordinator": (
        False,
        rust_tests("crates/security/chio-decoy/tests/coordinator.rs"),
        ["cargo", "test", "-p", "chio-decoy", "--test", "coordinator"],
    ),
    "decoy lifecycle": (
        False,
        rust_tests("crates/security/chio-decoy/tests/lifecycle.rs"),
        ["cargo", "test", "-p", "chio-decoy", "--test", "lifecycle"],
    ),
    "decoy matcher": (
        False,
        rust_tests("crates/security/chio-decoy/tests/matcher.rs"),
        ["cargo", "test", "-p", "chio-decoy", "--test", "matcher"],
    ),
    "decoy materialization": (
        False,
        materialize,
        ["cargo", "test", "-p", "chio-decoy", "--test", "materialize"],
    ),
    "sealed decoy registry API": (
        False,
        rust_tests("crates/security/chio-decoy/tests/registry.rs"),
        ["cargo", "test", "-p", "chio-decoy", "--test", "registry"],
    ),
    "decoy registry key rotation": (
        False,
        rust_tests("crates/security/chio-decoy/tests/registry_key_rotation.rs"),
        ["cargo", "test", "-p", "chio-decoy", "--test", "registry_key_rotation"],
    ),
    "signed watermark lifecycle": (
        False,
        rust_tests("crates/security/chio-decoy/tests/watermark.rs"),
        ["cargo", "test", "-p", "chio-decoy", "--test", "watermark"],
    ),
    "signed watermark vectors": (
        False,
        rust_tests("crates/security/chio-decoy/tests/watermark_vectors.rs"),
        ["cargo", "test", "-p", "chio-decoy", "--test", "watermark_vectors"],
    ),
    "pre-dispatch tripwire adapters": (
        True,
        [name for name in adapters if "tripwire" in name],
        [
            "cargo",
            "test",
            "-p",
            "chio-security-kernel",
            "--test",
            "adapters",
            "tripwire",
        ],
    ),
    "post-response watermark tripwire": (
        True,
        [name for name in adapters if "post_output_match" in name],
        [
            "cargo",
            "test",
            "-p",
            "chio-security-kernel",
            "--test",
            "adapters",
            "post_output_match",
        ],
    ),
    "sealed private registry store": (
        False,
        rust_tests("crates/platform/chio-store-sqlite/tests/sealed_decoy_registry.rs"),
        [
            "cargo",
            "test",
            "-p",
            "chio-store-sqlite",
            "--test",
            "sealed_decoy_registry",
        ],
    ),
    "native canary and honey-tool pre-dispatch denial": (
        True,
        [name for name in active_defense if name.endswith("_pre_dispatch_denial")],
        [
            "cargo",
            "test",
            "-p",
            "chio-conformance",
            "--test",
            "active_defense",
            "pre_dispatch_denial",
        ],
    ),
}

path = Path(sys.argv[1])
logical = path.read_text(encoding="utf-8").replace("\\\n", " ")
calls: dict[str, tuple[bool, list[str], list[str]]] = {}
cargo_test_lines = 0
for raw in logical.splitlines():
    line = raw.strip()
    if "cargo test" in line:
        cargo_test_lines += 1
    if not line.startswith("run_exact_target "):
        continue
    tokens = shlex.split(line)
    try:
        label = tokens[tokens.index("--label") + 1]
        inventory_start = tokens.index("--expected") + 1
        separator = tokens.index("--")
    except (ValueError, IndexError) as error:
        raise SystemExit(f"malformed exact deception call: {line}: {error}") from error
    inventory = tokens[inventory_start:separator]
    command = tokens[separator + 1 :]
    if not inventory:
        raise SystemExit(f"{label}: expected inventory is empty")
    if len(inventory) != len(set(inventory)):
        raise SystemExit(f"{label}: expected inventory contains a duplicate")
    if not all(re.fullmatch(r"[A-Za-z0-9_:]+", name) for name in inventory):
        raise SystemExit(f"{label}: invalid Rust test name in exact inventory")
    if command[:2] != ["cargo", "test"] or "--" in command:
        raise SystemExit(f"{label}: exact inventory does not wrap one unmodified Cargo test")
    if label in calls:
        raise SystemExit(f"duplicate deception gate label: {label}")
    calls[label] = ("--allow-filtered" in tokens, inventory, command)

if cargo_test_lines != len(calls):
    raise SystemExit(
        "every deception Cargo test command must be owned by one exact inventory call: "
        f"commands={cargo_test_lines} exact_calls={len(calls)}"
    )
if set(calls) != set(expected):
    raise SystemExit(
        "deception exact inventory labels changed: "
        f"missing={sorted(set(expected) - set(calls))!r} "
        f"unexpected={sorted(set(calls) - set(expected))!r}"
    )

for label, (expected_filtered, expected_inventory, expected_command) in expected.items():
    filtered, inventory, command = calls[label]
    if filtered != expected_filtered:
        raise SystemExit(f"{label}: incorrect filtered-test policy")
    if sorted(inventory) != sorted(expected_inventory):
        raise SystemExit(
            f"{label}: source and runner inventories differ: "
            f"expected={sorted(expected_inventory)!r} observed={sorted(inventory)!r}"
        )
    if command != expected_command:
        raise SystemExit(
            f"{label}: Cargo command changed: "
            f"expected={expected_command!r} observed={command!r}"
        )

total = sum(len(inventory) for _, inventory, _ in calls.values())
if total != 82:
    raise SystemExit(f"deception exact inventory total changed: expected=82 observed={total}")
PY
}

validate_runner "${runner}"

python3 scripts/tests/check-exact-cargo-test-inventory.test.py

python3 - "${verifier}" <<'PY'
import subprocess
import sys
import tempfile
from pathlib import Path


verifier = Path(sys.argv[1]).resolve()
listing = "alpha: test\nbeta: test\n"
valid_run = """running 2 tests
test alpha ... ok
test beta ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""


def invoke(observed_listing: str, observed_run: str) -> int:
    with tempfile.TemporaryDirectory(prefix="chio-deception-verifier-") as directory:
        root = Path(directory)
        list_path = root / "list.out"
        run_path = root / "run.out"
        list_path.write_text(observed_listing, encoding="utf-8")
        run_path.write_text(observed_run, encoding="utf-8")
        return subprocess.run(
            [
                "python3",
                str(verifier),
                "--label",
                "deception-hostile-fixture",
                "--list-output",
                str(list_path),
                "--run-output",
                str(run_path),
                "alpha",
                "beta",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode


hostile = {
    "missing": ("alpha: test\n", valid_run),
    "extra": (listing + "gamma: test\n", valid_run),
    "ignored": (
        listing,
        valid_run.replace("test beta ... ok", "test beta ... ignored").replace(
            "2 passed; 0 failed; 0 ignored", "1 passed; 0 failed; 1 ignored"
        ),
    ),
    "duplicate": ("alpha: test\nalpha: test\nbeta: test\n", valid_run),
    "zero": (
        listing,
        "running 0 tests\n\n"
        "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
        "2 filtered out; finished in 0.01s\n",
    ),
}
if invoke(listing, valid_run) != 0:
    raise SystemExit("exact inventory verifier rejected the valid deception fixture")
for mode, (observed_listing, observed_run) in hostile.items():
    if invoke(observed_listing, observed_run) == 0:
        raise SystemExit(f"exact inventory verifier accepted hostile {mode} evidence")
PY

work="$(mktemp -d "${TMPDIR:-/tmp}/chio-deception-gate-mutants.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
python3 - "${runner}" "${work}" <<'PY'
import sys
from pathlib import Path


runner = Path(sys.argv[1])
work = Path(sys.argv[2])
source = runner.read_text(encoding="utf-8")
inventory_line = "  honey_tool_pre_dispatch_denial \\\n"
missing_line = "  tripwire_content_digest_separates_identity_and_replays_exactly \\\n"
if source.count(inventory_line) != 1:
    raise SystemExit("honey-tool inventory line is absent or ambiguous")
if source.count(missing_line) != 1:
    raise SystemExit("tripwire inventory line is absent or ambiguous")

mutations = {
    "missing": source.replace(missing_line, "", 1),
    "extra": source.replace(
        inventory_line,
        inventory_line + "  unmandated_deception_case \\\n",
        1,
    ),
    "duplicate": source.replace(inventory_line, inventory_line * 2, 1),
    "zero": source.replace(inventory_line, "", 1),
    "ignored": source.replace(
        "  -- cargo test -p chio-conformance --test active_defense "
        "pre_dispatch_denial\n",
        "  -- cargo test -p chio-conformance --test active_defense "
        "pre_dispatch_denial -- --ignored\n",
        1,
    ),
}
for mode, content in mutations.items():
    (work / f"{mode}.sh").write_text(content, encoding="utf-8")
PY

for mutant in "${work}"/*.sh; do
  set +e
  validate_runner "${mutant}" >/dev/null 2>&1
  status=$?
  set -e
  if [[ "${status}" -eq 0 ]]; then
    echo "deception gate accepted hostile $(basename "${mutant}" .sh) mutation" >&2
    exit 1
  fi
done

echo "Deception security gate contract passed (12 exact inventories, 82 tests)"
