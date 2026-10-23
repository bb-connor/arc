#!/usr/bin/env python3
"""Keep the `wrapper-capture` feature out of every production build.

`chio-core-types` defines `wrapper-capture`, a test-harness feature that
records each body the signing wrapper covers. Only
`scripts/capture-wrapper-bodies.sh` enables it, from the command line, for
one test run. This gate fails when:

- the feature is in `default`, implies anything other than `std`, or is
  missing from `crates/core/chio-core-types/Cargo.toml`;
- any tracked file outside the hook, the manifest, the harness and this
  gate names the feature, so no manifest, workflow, Dockerfile, build
  script or other source file can enable it or compile code under it.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from pathlib import Path

FEATURE = "wrapper-capture"
CORE_MANIFEST = "crates/core/chio-core-types/Cargo.toml"
HOOK_FILES = {
    "crates/core/chio-core-types/src/crypto/wrapper.rs",
    "crates/core/chio-core-types/src/crypto/wrapper_capture.rs",
}
NAMING_FILES = HOOK_FILES | {
    CORE_MANIFEST,
    "scripts/capture-wrapper-bodies.sh",
    "scripts/check-wrapper-capture-scope.py",
    "scripts/check-signing-exemptions.py",
    "scripts/tests/check-signing-exemptions.test.py",
    "scripts/tests/check-wrapper-capture-scope.test.py",
}


def tracked_files(root: Path) -> list[str]:
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout.decode("utf-8")
    return sorted(path for path in listed.split("\0") if path)


def check(root: Path) -> list[str]:
    errors: list[str] = []
    manifest_path = root / CORE_MANIFEST
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"{CORE_MANIFEST}: {error}"]
    features = manifest.get("features", {})
    if features.get(FEATURE) != ["std"]:
        errors.append(f'{CORE_MANIFEST}: [features] {FEATURE} must be exactly ["std"]')
    if FEATURE in features.get("default", []):
        errors.append(f"{CORE_MANIFEST}: {FEATURE} must not be a default feature")
    for name, implied in features.items():
        if name != FEATURE and any(FEATURE in item for item in implied):
            errors.append(f"{CORE_MANIFEST}: feature {name} implies {FEATURE}")

    for rel in tracked_files(root):
        path = root / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if FEATURE not in text:
            continue
        if rel not in NAMING_FILES:
            errors.append(f"{rel}: names {FEATURE}; only the capture harness may enable it")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    errors = check(args.root.resolve())
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"OK {FEATURE} is confined to the capture harness")
    return 0


if __name__ == "__main__":
    sys.exit(main())
