#!/usr/bin/env python3
"""Require the isolated portable consumer to use workspace-approved packages."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import tomllib

CONSUMER = ("chio-recovery-portable-consumer", "0.0.0", None, None)


def identity(package: dict) -> tuple[str, str, str | None, str | None]:
    name, version = package.get("name"), package.get("version")
    source, checksum = package.get("source"), package.get("checksum")
    if not isinstance(name, str) or not isinstance(version, str):
        raise ValueError("package identity is incomplete")
    if source is not None and not isinstance(source, str):
        raise ValueError("package source is invalid")
    if checksum is not None and not isinstance(checksum, str):
        raise ValueError("package checksum is invalid")
    if source is not None and source.startswith("registry+") and not checksum:
        raise ValueError("registry package has no checksum")
    return name, version, source, checksum


def audit_locks(workspace: dict, consumer: dict) -> tuple[str, ...]:
    """Compare complete source identities, allowing only the local fixture root."""
    approved = {identity(package) for package in workspace["package"]}
    seen = set()
    findings = []
    for package in consumer["package"]:
        key = identity(package)
        display = f"{key[0]} {key[1]}"
        if key in seen:
            findings.append(f"duplicate package: {display}")
        elif key != CONSUMER and key not in approved:
            findings.append(f"outside workspace inventory: {display}")
        seen.add(key)
    if CONSUMER not in seen:
        findings.append("portable consumer root is missing")
    return tuple(sorted(findings))


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-lock", type=Path, default=root / "Cargo.lock")
    parser.add_argument("--consumer-lock", type=Path,
                        default=root / "fixtures/recovery-portable-consumer/Cargo.lock")
    args = parser.parse_args()
    try:
        workspace = tomllib.loads(args.workspace_lock.read_text(encoding="utf-8"))
        consumer = tomllib.loads(args.consumer_lock.read_text(encoding="utf-8"))
        findings = audit_locks(workspace, consumer)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, ValueError, KeyError, TypeError):
        print("portable lock inventory cannot be validated", file=sys.stderr)
        return 1
    if findings:
        print(f"portable lock has {len(findings)} inventory violation(s)", file=sys.stderr)
        for finding in findings[:20]:
            print(finding, file=sys.stderr)
        return 1
    print("portable lock uses only workspace-approved package identities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
