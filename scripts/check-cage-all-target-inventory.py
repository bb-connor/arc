#!/usr/bin/env python3
"""Verify the exact Linux x86_64 chio-cage all-target test inventory."""

from __future__ import annotations

import argparse
import hashlib
import re
import tomllib
from collections import Counter, defaultdict
from pathlib import Path


EXPECTED_COUNTS = {
    "lib": 20,
    "bin_chio_cage_init": 0,
    "lib_chio_cage_plan": 5,
    "lib_chio_cage_init": 1,
    "entrypoint": 1,
    "enforcement_evidence": 8,
    "linux_compile": 15,
    "linux_enforcement": 29,
}
EXPECTED_TOTAL = 79
EXPECTED_SHA256 = "42a48ab3aa04f35e4f12075c8eb73c8a7ef3da2cd4356fcdcd6efb3b0fe0a90c"
EXPECTED_INTEGRATION_TARGETS = {
    "enforcement_evidence.rs",
    "linux_compile.rs",
    "linux_enforcement.rs",
}
TEST_DECLARATION = re.compile(
    r"(?P<attrs>(?:\s*#\[[^\]]+\]\s*)+)" r"(?:async\s+)?fn\s+(?P<name>[A-Za-z0-9_]+)"
)
TEST_ATTRIBUTE = re.compile(r"#\[(?:tokio::)?test(?:\([^]]*\))?\]")
TARGET_HEADER = re.compile(
    r"Running (?:(?P<unit>unittests) |(?P<integration>tests/))" r"(?P<path>[^ ]+) \((?P<exe>[^)]+)\)"
)
TEST_RESULT = re.compile(
    r"test (?P<name>[A-Za-z0-9_:]+) \.\.\. (?P<status>ok|ignored|FAILED)"
)
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SUMMARY = re.compile(
    r"test result: (?P<outcome>ok|FAILED)\. (?P<passed>[0-9]+) passed; "
    r"(?P<failed>[0-9]+) failed; (?P<ignored>[0-9]+) ignored; "
    r"(?P<measured>[0-9]+) measured; (?P<filtered>[0-9]+) filtered out;"
)
RUNNING = re.compile(r"running (?P<count>[0-9]+) tests?")


class InventoryError(RuntimeError):
    """The source or execution inventory is not exact."""


def test_declarations(path: Path) -> list[tuple[str, str]]:
    declarations = []
    for match in TEST_DECLARATION.finditer(path.read_text(encoding="utf-8")):
        attributes = match.group("attrs")
        if TEST_ATTRIBUTE.search(attributes):
            declarations.append((match.group("name"), attributes))
    return declarations


def source_inventory(root: Path) -> dict[str, list[str]]:
    crate = root / "crates/security/chio-cage"
    source = crate / "src"
    tests = crate / "tests"
    if not source.is_dir() or not tests.is_dir():
        raise InventoryError("chio-cage source tree is incomplete")

    manifest = tomllib.loads((crate / "Cargo.toml").read_text(encoding="utf-8"))
    if manifest.get("bin") or (source / "bin").exists():
        raise InventoryError("chio-cage must not package the privileged helper")
    helper = root / "crates/security/chio-cage-init"
    plan = root / "crates/security/chio-cage-plan"
    helper_manifest = tomllib.loads((helper / "Cargo.toml").read_text())
    if helper_manifest.get("package", {}).get("name") != "chio-cage-init" or not (helper / "src/main.rs").is_file():
        raise InventoryError("standalone chio-cage-init binary target is missing")
    if {p.name for p in (helper / "tests").glob("*.rs")} != {"entrypoint.rs"}:
        raise InventoryError("chio-cage-init integration target inventory changed")
    if manifest.get("example") or manifest.get("bench"):
        raise InventoryError(
            "chio-cage example or benchmark target inventory is not empty"
        )
    for directory_name in ("examples", "benches"):
        directory = crate / directory_name
        if directory.is_dir() and any(directory.rglob("*.rs")):
            raise InventoryError(
                f"chio-cage implicit {directory_name} target inventory is not empty"
            )

    integration_files = {
        path.relative_to(tests).as_posix() for path in tests.rglob("*.rs")
    }
    if integration_files != EXPECTED_INTEGRATION_TARGETS:
        raise InventoryError(
            "chio-cage integration target inventory changed: "
            f"expected={sorted(EXPECTED_INTEGRATION_TARGETS)!r} "
            f"observed={sorted(integration_files)!r}"
        )

    inventory: dict[str, list[str]] = defaultdict(list)
    for owner, target in [(crate, "lib"), (plan, "lib_chio_cage_plan"), (helper, "lib_chio_cage_init")]:
        for path in sorted((owner / "src").rglob("*.rs")):
            relative = path.relative_to(owner).as_posix()
            if relative == "src/main.rs":
                if test_declarations(path):
                    raise InventoryError("helper main must delegate tests to its library and entrypoint target")
                continue
            for name, attributes in test_declarations(path):
                if relative == "src/launch.rs" and name == "unsupported_platform_keeps_a_fail_closed_signal_surface":
                    continue
                if 'not(target_os = "linux")' in attributes or 'feature = "enforcement-mutants"' in attributes:
                    continue
                inventory[target].append(name)
    inventory["entrypoint"] = [name for name, _ in test_declarations(helper / "tests/entrypoint.rs")]

    for file_name in sorted(EXPECTED_INTEGRATION_TARGETS):
        target = Path(file_name).stem
        for name, attributes in test_declarations(tests / file_name):
            if 'feature = "enforcement-mutants"' in attributes:
                continue
            inventory[target].append(name)

    for target in EXPECTED_COUNTS:
        inventory.setdefault(target, [])
        duplicates = sorted(
            name for name, count in Counter(inventory[target]).items() if count != 1
        )
        if duplicates:
            raise InventoryError(
                f"chio-cage {target} source inventory contains duplicate names: {duplicates!r}"
            )
        inventory[target].sort()

    observed_counts = {target: len(inventory[target]) for target in EXPECTED_COUNTS}
    if observed_counts != EXPECTED_COUNTS:
        raise InventoryError(
            "chio-cage Linux source target counts changed: "
            f"expected={EXPECTED_COUNTS!r} observed={observed_counts!r}"
        )

    canonical = sorted(
        f"{target}::{name}" for target in EXPECTED_COUNTS for name in inventory[target]
    )
    digest = hashlib.sha256(("\n".join(canonical) + "\n").encode("utf-8")).hexdigest()
    if len(canonical) != EXPECTED_TOTAL or digest != EXPECTED_SHA256:
        raise InventoryError(
            "chio-cage Linux source commitment changed: "
            f"expected_count={EXPECTED_TOTAL} observed_count={len(canonical)} "
            f"expected_sha256={EXPECTED_SHA256} observed_sha256={digest}"
        )
    return dict(inventory)


def header_target(kind: str, path: str, executable: str) -> str:
    if kind == "unittests" and path == "src/lib.rs":
        name = Path(executable).name.split("-", 1)[0]
        targets = {"chio_cage": "lib", "chio_cage_plan": "lib_chio_cage_plan", "chio_cage_init": "lib_chio_cage_init"}
        if name not in targets:
            raise InventoryError(f"unrecognized confinement library {name}")
        return targets[name]
    if kind == "unittests" and path == "src/main.rs" and Path(executable).name.startswith("chio_cage_init-"):
        return "bin_chio_cage_init"
    if kind == "tests/" and path.endswith(".rs"):
        return Path(path).stem
    raise InventoryError(f"unrecognized chio-cage target header: {kind}{path}")


def verify_execution(output: Path, expected: dict[str, list[str]]) -> None:
    headers: Counter[str] = Counter()
    running_counts: dict[str, list[int]] = defaultdict(list)
    results: dict[str, list[tuple[str, str]]] = defaultdict(list)
    summaries: dict[str, list[tuple[str, int, int, int, int, int]]] = defaultdict(list)
    current: str | None = None

    for raw_line in output.read_text(encoding="utf-8").splitlines():
        line = ANSI_ESCAPE.sub("", raw_line).strip()
        if match := TARGET_HEADER.search(line):
            kind = "unittests" if match.group("unit") is not None else "tests/"
            current = header_target(kind, match.group("path"), match.group("exe"))
            if current not in EXPECTED_COUNTS:
                raise InventoryError(f"unexpected chio-cage test target {current}")
            headers[current] += 1
            continue
        if line.startswith("Doc-tests chio_cage"):
            current = None
            continue
        if current is None:
            continue
        if match := RUNNING.fullmatch(line):
            running_counts[current].append(int(match.group("count")))
            continue
        if match := TEST_RESULT.fullmatch(line):
            results[current].append(
                (match.group("name").rsplit("::", 1)[-1], match.group("status"))
            )
            continue
        if match := SUMMARY.match(line):
            summaries[current].append(
                (
                    match.group("outcome"),
                    int(match.group("passed")),
                    int(match.group("failed")),
                    int(match.group("ignored")),
                    int(match.group("measured")),
                    int(match.group("filtered")),
                )
            )
            current = None

    if dict(headers) != {target: 1 for target in EXPECTED_COUNTS}:
        raise InventoryError(
            "chio-cage all-target execution headers are not exact: "
            f"observed={dict(headers)!r}"
        )

    for target, expected_names in expected.items():
        count = len(expected_names)
        if running_counts[target] != [count]:
            raise InventoryError(
                f"chio-cage {target} running count is not exactly {count}: "
                f"{running_counts[target]!r}"
            )
        observed_results = results[target]
        passed = sorted(name for name, status in observed_results if status == "ok")
        nonpassing = sorted(
            (name, status) for name, status in observed_results if status != "ok"
        )
        if passed != expected_names or nonpassing:
            missing = sorted(set(expected_names) - set(passed))
            unexpected = sorted(set(passed) - set(expected_names))
            raise InventoryError(
                f"chio-cage {target} execution inventory mismatch: "
                f"missing={missing!r} unexpected={unexpected!r} "
                f"nonpassing={nonpassing!r}"
            )
        if len(observed_results) != count:
            raise InventoryError(
                f"chio-cage {target} execution contains duplicate test results"
            )
        if summaries[target] != [("ok", count, 0, 0, 0, 0)]:
            raise InventoryError(
                f"chio-cage {target} summary is not exact: {summaries[target]!r}"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--run-output", type=Path)
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args()
    if args.source_only == (args.run_output is not None):
        parser.error("choose exactly one of --source-only or --run-output")

    try:
        expected = source_inventory(args.root.resolve())
        if args.run_output is not None:
            verify_execution(args.run_output, expected)
    except (InventoryError, OSError, UnicodeError) as error:
        raise SystemExit(str(error)) from error

    print(
        "chio-cage Linux all-target inventory passed "
        f"({EXPECTED_TOTAL} tests; {EXPECTED_SHA256})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
