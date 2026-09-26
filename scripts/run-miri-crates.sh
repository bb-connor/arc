#!/usr/bin/env bash
# Run the committed Miri crate list, or validate and print it.
#
# Miri finds undefined behaviour by interpreting the tests it is given, so a
# green run proves something only about the code those tests executed. The
# list at .config/miri-crates.toml therefore records, per crate, why it is on
# the list (how many of its unsafe sites a unit test reaches), which tests are
# skipped and for which of the two reasons Miri cannot execute them (a call
# into C, or a syscall Miri does not implement), and which crates with unsafe
# code are excluded or ineligible and why. A skip or exclusion with any other
# reason is refused here, so the list cannot quietly grow a third category.
#
# Usage:
#   scripts/run-miri-crates.sh            run every listed crate's unit tests
#   scripts/run-miri-crates.sh --list     validate the list and print the plan
#   scripts/run-miri-crates.sh --config <path>   use another list (self-tests)
#
# Each crate runs to completion or its time box; a failure in one crate does
# not stop the others, and the exit status is 1 if any crate failed.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - "$@" <<'PY'
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib

REASON_PREFIXES = ("calls into C:", "syscall:")
TOOLCHAIN = re.compile(r"\Anightly-\d{4}-\d{2}-\d{2}\Z")


def fail(message: str) -> None:
    print(f"run-miri-crates: {message}", file=sys.stderr)
    raise SystemExit(1)


def reasoned(entry: dict, key: str, where: str) -> str:
    reason = entry.get(key)
    if not isinstance(reason, str) or not reason.startswith(REASON_PREFIXES):
        fail(
            f"{where}: {key} must start with one of {', '.join(repr(p) for p in REASON_PREFIXES)}; "
            f"got {reason!r}"
        )
    return reason


def load(path: str) -> dict:
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"{path}: {exc}")
    toolchain = data.get("toolchain")
    if not isinstance(toolchain, str) or not TOOLCHAIN.match(toolchain):
        fail(f"{path}: toolchain must be a nightly pinned by date, got {toolchain!r}")
    if not isinstance(data.get("miriflags", ""), str):
        fail(f"{path}: miriflags must be a string")
    box = data.get("timeout_seconds", 1800)
    if not isinstance(box, int) or box <= 0:
        fail(f"{path}: timeout_seconds must be a positive integer")
    names: dict[str, str] = {}
    for crate in data.get("crate", []):
        name = crate.get("name")
        if not isinstance(name, str) or not name:
            fail(f"{path}: a [[crate]] entry has no name")
        if name in names:
            fail(f"{path}: {name} appears twice ({names[name]} and crate)")
        names[name] = "crate"
        for key in ("unsafe_sites", "reached"):
            if not isinstance(crate.get(key), int) or crate[key] < 0:
                fail(f"{path}: {name}: {key} must be a non-negative integer")
        if crate["reached"] == 0:
            fail(f"{path}: {name}: no unit test reaches its unsafe code; it does not belong on the list")
        seen: set[str] = set()
        for skip in crate.get("skip", []):
            test = skip.get("test")
            if not isinstance(test, str) or "::" not in test:
                fail(f"{path}: {name}: skip needs a module-qualified test name, got {test!r}")
            if test in seen:
                fail(f"{path}: {name}: skip {test} appears twice")
            seen.add(test)
            reasoned(skip, "reason", f"{path}: {name}: skip {test}")
    for section in ("excluded", "ineligible"):
        for entry in data.get(section, []):
            name = entry.get("name")
            if not isinstance(name, str) or not name:
                fail(f"{path}: a [[{section}]] entry has no name")
            if name in names:
                fail(f"{path}: {name} appears twice ({names[name]} and {section})")
            names[name] = section
            if section == "excluded":
                reasoned(entry, "reason", f"{path}: excluded {name}")
            elif not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
                fail(f"{path}: ineligible {name}: reason is required")
    return data


def command(data: dict, crate: dict) -> list[str]:
    argv = ["cargo", f"+{data['toolchain']}", "miri", "test", "-p", crate["name"], "--lib"]
    skips = crate.get("skip", [])
    if skips:
        argv.append("--")
        for skip in skips:
            argv.extend(["--skip", skip["test"]])
    return argv


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=".config/miri-crates.toml")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    data = load(args.config)
    crates = data.get("crate", [])
    box = data.get("timeout_seconds", 1800)
    print(
        f"miri crate list: {len(crates)} crates, {sum(len(c.get('skip', [])) for c in crates)} skipped tests, "
        f"{len(data.get('excluded', []))} excluded, {len(data.get('ineligible', []))} ineligible; "
        f"toolchain {data['toolchain']}, MIRIFLAGS {data.get('miriflags', '')!r}, {box} s per crate"
    )
    for crate in crates:
        print("  " + " ".join(command(data, crate)))
    if args.list:
        return 0
    failed: list[str] = []
    for crate in crates:
        argv = command(data, crate)
        print(f"\n== {crate['name']}", flush=True)
        try:
            result = subprocess.run(
                argv,
                env={**__import__("os").environ, "MIRIFLAGS": data.get("miriflags", "")},
                timeout=box,
            )
            if result.returncode != 0:
                failed.append(f"{crate['name']} (exit {result.returncode})")
        except subprocess.TimeoutExpired:
            failed.append(f"{crate['name']} (no result within {box} s)")
    if failed:
        print("\nmiri crates failed: " + ", ".join(failed), file=sys.stderr)
        return 1
    print("\nmiri crates passed")
    return 0


raise SystemExit(main())
PY
