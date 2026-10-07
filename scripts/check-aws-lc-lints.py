#!/usr/bin/env python3
"""Enforce the standalone fork's deny floor and reviewed panic dispositions.

The forced-warning pass measures even explicitly allowed sites. Its successful
compiler exit alone is never acceptance: every diagnostic must match the
independently reviewed, source-bound inventory.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FORK = Path("third_party/aws-lc-rs-chio")
RECORD = Path("supply-chain/aws-lc-lint-exceptions.json")
LINTS = ("clippy::unwrap_used", "clippy::expect_used")
FLOOR = "#![deny(clippy::unwrap_used, clippy::expect_used)]"
PROFILES = {
    "default-legacy": ["--features", "legacy-des"],
    "fips": ["--no-default-features", "--features", "alloc,fips,ring-io,ring-sig-verify"],
}


class LintPolicyError(ValueError):
    """The fork no longer meets the reviewed lint contract."""


def verify_source(fork: Path, record: dict) -> None:
    if record.get("schema") != "chio.aws-lc-lint-exceptions.v1":
        raise LintPolicyError("unrecognized lint inventory")
    if record.get("profiles") != PROFILES:
        raise LintPolicyError("reviewed lint feature selections changed")
    for name in ("src/lib.rs", "build.rs"):
        if name not in record["files"]:
            raise LintPolicyError(f"unbound standalone deny floor: {name}")
        if FLOOR not in (fork / name).read_text().splitlines():
            raise LintPolicyError(f"standalone deny floor missing: {name}")
    for name, expected in record["files"].items():
        path = fork / name
        if (path.is_symlink() or not path.resolve().is_relative_to(fork.resolve())
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise LintPolicyError(f"lint disposition source changed: {name}")
    ids = set()
    for entry in record["exceptions"]:
        if entry["id"] in ids or not entry["item"] or not entry["rationale"]:
            raise LintPolicyError("duplicate or unattributed lint disposition")
        ids.add(entry["id"])
        if entry["file"] not in record["files"] or entry["lint"] not in LINTS:
            raise LintPolicyError("unbound lint disposition")
        if not entry["sites"] or any(p not in PROFILES for p in entry["sites"]):
            raise LintPolicyError("unmeasured lint disposition")
    if not ids:
        raise LintPolicyError("missing reviewed lint dispositions")


def diagnostics(output: str, fork: Path) -> Counter:
    found = Counter()
    for line in output.splitlines():
        event = json.loads(line)
        if event.get("reason") != "compiler-message":
            continue
        message = event["message"]
        lint = (message.get("code") or {}).get("code")
        if lint not in LINTS:
            continue
        target = Path(event["target"]["src_path"]).resolve()
        if not target.is_relative_to(fork.resolve()):
            continue
        spans = [span for span in message["spans"] if span["is_primary"]]
        if len(spans) != 1:
            raise LintPolicyError("ambiguous compiler lint span")
        span = spans[0]
        path = Path(span["file_name"])
        if not path.is_absolute():
            path = fork / path
        if not path.resolve().is_relative_to(fork.resolve()):
            raise LintPolicyError("compiler lint outside reviewed fork")
        name = path.resolve().relative_to(fork.resolve()).as_posix()
        found[(name, lint, span["byte_start"], span["byte_end"])] += 1
    return found


def verify_diagnostics(actual: Counter, record: dict, profile: str) -> None:
    expected = Counter()
    for entry in record["exceptions"]:
        for start, end in entry["sites"].get(profile, []):
            expected[(entry["file"], entry["lint"], start, end)] += 1
    if not expected or actual != expected:
        raise LintPolicyError(
            f"{profile} lint sites differ: unexpected={list((actual - expected).elements())}, "
            f"missing={list((expected - actual).elements())}"
        )


def run_clippy(fork: Path, features: list[str], *, force_warn: bool) -> str:
    command = ["cargo", "clippy", "--manifest-path", str(fork / "Cargo.toml"),
               "--locked", "--lib", *features, "--message-format=json", "--"]
    for lint in LINTS:
        command.extend(["--force-warn" if force_warn else "--deny", lint])
    result = subprocess.run(command, cwd=fork, text=True, stdout=subprocess.PIPE)
    if result.returncode:
        for line in result.stdout.splitlines():
            event = json.loads(line)
            if event.get("reason") == "compiler-message":
                rendered = event["message"].get("rendered")
                if rendered:
                    print(rendered, file=sys.stderr, end="")
        raise subprocess.CalledProcessError(result.returncode, command)
    return result.stdout


def main() -> int:
    try:
        fork = ROOT / FORK
        record = json.loads((ROOT / RECORD).read_text())
        verify_source(fork, record)
        # Keep direct invocation as safe for the audited tree as the composite.
        target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target/aws-lc-audit")).resolve()
        if target.is_relative_to(fork.resolve()):
            raise LintPolicyError("Cargo output must live outside the audited fork")
        os.environ["CARGO_TARGET_DIR"] = str(target)
        for profile, features in PROFILES.items():
            run_clippy(fork, features, force_warn=False)
            output = run_clippy(fork, features, force_warn=True)
            actual = diagnostics(output, fork)
            verify_diagnostics(actual, record, profile)
            print(f"AWS-LC {profile}: deny floor passed; {sum(actual.values())} reviewed sites matched")
    except (LintPolicyError, OSError, ValueError, KeyError, TypeError,
            subprocess.CalledProcessError) as error:
        print(f"AWS-LC lint qualification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
