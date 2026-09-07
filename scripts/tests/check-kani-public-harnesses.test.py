#!/usr/bin/env python3
"""Mutation self-tests for the public Kani harness enrollment checker."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts/check-kani-public-harnesses.py"
SOURCE = REPO_ROOT / "crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs"
MULTI_MANIFEST = REPO_ROOT / ".kani/harnesses.toml"
PUBLIC_MANIFEST = REPO_ROOT / "formal/rust-verification/kani-public-harnesses.toml"


def invoke(source: Path, multi_manifest: Path, public_manifest: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CHECKER),
            "--source",
            str(source),
            "--multi-manifest",
            str(multi_manifest),
            "--public-manifest",
            str(public_manifest),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AssertionError(
            f"expected one mutation target in {path}, found {text.count(old)}"
        )
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def require_failure(result: subprocess.CompletedProcess[str], label: str, needle: str) -> None:
    if result.returncode == 0:
        raise AssertionError(f"{label} unexpectedly passed")
    output = result.stdout + result.stderr
    if needle not in output:
        raise AssertionError(f"{label} did not report {needle!r}:\n{output}")


def main() -> int:
    baseline = invoke(SOURCE, MULTI_MANIFEST, PUBLIC_MANIFEST)
    if baseline.returncode != 0:
        raise AssertionError(
            "baseline public Kani harness contract failed:\n"
            + baseline.stdout
            + baseline.stderr
        )

    with tempfile.TemporaryDirectory(prefix="chio-kani-public-harnesses-") as raw:
        work = Path(raw)
        source = work / "kani_public_harnesses.rs"
        multi_manifest = work / "harnesses.toml"
        public_manifest = work / "kani-public-harnesses.toml"

        def reset() -> None:
            shutil.copyfile(SOURCE, source)
            shutil.copyfile(MULTI_MANIFEST, multi_manifest)
            shutil.copyfile(PUBLIC_MANIFEST, public_manifest)

        reset()
        replace_once(
            source,
            "#[kani::proof]\npub fn verify_captured_invocation_count_monotonic()",
            "pub fn verify_captured_invocation_count_monotonic()",
        )
        require_failure(
            invoke(source, multi_manifest, public_manifest),
            "source proof deletion mutation",
            "Kani public harness parity mismatch",
        )

        reset()
        replace_once(
            multi_manifest,
            'harness = "verify_replay_fingerprint_uniqueness"',
            'harness = "verify_replay_fingerprint_unique"',
        )
        require_failure(
            invoke(source, multi_manifest, public_manifest),
            "multi-crate manifest drift mutation",
            ".kani chio-kernel-core lane=pr set",
        )

        reset()
        replace_once(
            public_manifest,
            '  "verify_family_binding_preservation",',
            "",
        )
        require_failure(
            invoke(source, multi_manifest, public_manifest),
            "formal PR-lane deletion mutation",
            "formal lanes.pr set",
        )

        reset()
        old_name = "verify_threshold_distinct_signers"
        new_name = "verify_threshold_unique_signers"
        replace_once(source, f"pub fn {old_name}()", f"pub fn {new_name}()")
        replace_once(
            multi_manifest,
            f'harness = "{old_name}"',
            f'harness = "{new_name}"',
        )
        replace_once(
            public_manifest,
            f'  "{old_name}",',
            f'  "{new_name}",',
        )
        require_failure(
            invoke(source, multi_manifest, public_manifest),
            "coordinated required-name drift mutation",
            old_name,
        )

    print("check-kani-public-harnesses.test.py: all mutation assertions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
