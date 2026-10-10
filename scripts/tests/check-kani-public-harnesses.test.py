#!/usr/bin/env python3
"""Mutation self-tests for the public Kani harness enrollment checker."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts/check-kani-public-harnesses.py"
SOURCE = REPO_ROOT / "crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs"
MULTI_MANIFEST = REPO_ROOT / ".kani/harnesses.toml"
PUBLIC_MANIFEST = REPO_ROOT / "formal/rust-verification/kani-public-harnesses.toml"
TRUST_SOURCES = {
    crate: REPO_ROOT / f"crates/trust/{crate}/src/kani_public_harnesses.rs"
    for crate in ("chio-weights", "chio-attest-verify")
}


def toml_value(value: object) -> str:
    if isinstance(value, dict):
        return (
            "{ "
            + ", ".join(
                f"{json.dumps(key)} = {toml_value(member)}"
                for key, member in value.items()
            )
            + " }"
        )
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(member) for member in value) + "]"
    return json.dumps(value)


def write_toml(path: Path, document: dict) -> None:
    path.write_text(
        "\n".join(f"{key} = {toml_value(value)}" for key, value in document.items())
        + "\n"
    )


def copied_fixture(work: Path) -> tuple[Path, Path, Path, dict[str, Path]]:
    source = work / "kani_public_harnesses.rs"
    multi = work / "harnesses.toml"
    public = work / "kani-public-harnesses.toml"
    for original, copied in (
        (SOURCE, source),
        (MULTI_MANIFEST, multi),
        (PUBLIC_MANIFEST, public),
    ):
        shutil.copyfile(original, copied)
    trusts = {crate: work / f"{crate}.rs" for crate in TRUST_SOURCES}
    for crate, copied in trusts.items():
        shutil.copyfile(TRUST_SOURCES[crate], copied)
    return source, multi, public, trusts


def test_trust_bound_drift() -> None:
    with tempfile.TemporaryDirectory(prefix="chio-kani-trust-bound-") as raw:
        source, multi, public, _ = copied_fixture(Path(raw))
        document = tomllib.loads(multi.read_text())
        row = next(
            row
            for row in document["harness"]
            if row["harness"] == "public_weights_hash_of_determinism_and_shape"
        )
        row["default_unwind"] += 1
        write_toml(multi, document)
        require_failure(
            invoke(source, multi, public),
            "trust bound drift",
            "source unwind declaration",
        )


def invoke(
    source: Path,
    multi_manifest: Path,
    public_manifest: Path,
    *,
    trust_sources: dict[str, Path] | None = None,
    extra_args: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    trusts = (
        {crate: source.parent / f"{crate}.rs" for crate in TRUST_SOURCES}
        if trust_sources is None
        else trust_sources
    )
    trust_args = [
        argument
        for crate, path in trusts.items()
        for argument in ("--trust-source", f"{crate}={path}")
    ]
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
            *trust_args,
            *extra_args,
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


def require_failure(
    result: subprocess.CompletedProcess[str], label: str, needle: str
) -> None:
    if result.returncode == 0:
        raise AssertionError(f"{label} unexpectedly passed")
    output = result.stdout + result.stderr
    if needle not in output:
        raise AssertionError(f"{label} did not report {needle!r}:\n{output}")


def test_attest_profile_is_standalone() -> None:
    with tempfile.TemporaryDirectory(prefix="chio-kani-attest-profile-") as raw:
        source, multi, public, trusts = copied_fixture(Path(raw))
        document = tomllib.loads(multi.read_text())
        row = next(
            row
            for row in document["harness"]
            if row["harness"] == "public_expect_report_data_determinism_and_binding"
        )
        row.pop("public_key_hex_unwind", None)
        write_toml(multi, document)
        observed = invoke(source, multi, public, trust_sources=trusts)
        if observed.returncode:
            raise AssertionError(
                "standalone attest profile rejected:\n" + observed.stderr
            )
        row["public_key_hex_unwind"] = 0
        write_toml(multi, document)
        require_failure(
            invoke(source, multi, public, trust_sources=trusts),
            "stale attest hex selector",
            "standalone P256 encoding bounds",
        )


def main() -> int:
    baseline = invoke(
        SOURCE, MULTI_MANIFEST, PUBLIC_MANIFEST, trust_sources=TRUST_SOURCES
    )
    if baseline.returncode != 0:
        raise AssertionError(
            "baseline public Kani harness contract failed:\n"
            + baseline.stdout
            + baseline.stderr
        )

    test_attest_profile_is_standalone()

    with tempfile.TemporaryDirectory(prefix="chio-kani-public-harnesses-") as raw:
        work = Path(raw)
        source = work / "kani_public_harnesses.rs"
        multi_manifest = work / "harnesses.toml"
        public_manifest = work / "kani-public-harnesses.toml"

        def reset() -> None:
            shutil.copyfile(SOURCE, source)
            shutil.copyfile(MULTI_MANIFEST, multi_manifest)
            shutil.copyfile(PUBLIC_MANIFEST, public_manifest)
            for crate, original in TRUST_SOURCES.items():
                shutil.copyfile(original, work / f"{crate}.rs")

        test_trust_bound_drift()
        for surface in ("multi", "public"):
            reset()
            path = multi_manifest if surface == "multi" else public_manifest
            document = tomllib.loads(path.read_text())
            if surface == "multi":
                document["harness"][0]["unknown_profile"] = 17
            else:
                document["unknown_profile"] = {}
            write_toml(path, document)
            require_failure(
                invoke(source, multi_manifest, public_manifest),
                "unknown enrollment key",
                "unknown keys",
            )
        reset()
        for mappings in ({}, {"chio-weights": work / "chio-weights.rs"}):
            require_failure(
                invoke(source, multi_manifest, public_manifest, trust_sources=mappings),
                "incomplete copied-source mapping",
                "trust source mappings",
            )
        for argument in (
            "chio-unknown=missing.rs",
            "chio-weights=",
            "chio-weights",
            f"chio-weights={work / 'chio-weights.rs'}",
        ):
            require_failure(
                invoke(
                    source,
                    multi_manifest,
                    public_manifest,
                    extra_args=("--trust-source", argument),
                ),
                "malformed or duplicate trust source mapping",
                "trust source",
            )
        mappings = {crate: work / f"{crate}.rs" for crate in TRUST_SOURCES}
        mappings["chio-weights"] = work / "missing.rs"
        require_failure(
            invoke(source, multi_manifest, public_manifest, trust_sources=mappings),
            "copied trust source missing",
            "unable to load",
        )

        for crate, names in (
            (
                "chio-weights",
                (
                    "public_weights_hash_of_determinism_and_shape",
                    "public_model_card_require_live_fail_closed",
                    "public_weights_error_urn_is_stable",
                    "public_model_card_new_pins_schema_version",
                ),
            ),
            (
                "chio-attest-verify",
                ("public_expect_report_data_determinism_and_binding",),
            ),
        ):
            for name in names:
                for replacement in (0, True, "8", 4294967296):
                    reset()
                    document = tomllib.loads(multi_manifest.read_text())
                    next(row for row in document["harness"] if row["harness"] == name)[
                        "default_unwind"
                    ] = replacement
                    write_toml(multi_manifest, document)
                    require_failure(
                        invoke(source, multi_manifest, public_manifest),
                        "invalid trust default unwind",
                        "source unwind declaration",
                    )
                for mutation in (
                    "missing_attribute",
                    "missing_proof",
                    "duplicate_attribute",
                    "zero_attribute",
                ):
                    reset()
                    document = tomllib.loads(multi_manifest.read_text())
                    bound = next(
                        row for row in document["harness"] if row["harness"] == name
                    )["default_unwind"]
                    trust_path = work / f"{crate}.rs"
                    declaration = re.search(
                        r"(?m)(?:^#\[kani::[^\n]+\]\n)+^pub fn "
                        + re.escape(name)
                        + r"\(\)",
                        trust_path.read_text(),
                    )
                    if declaration is None:
                        raise AssertionError(f"missing fixture declaration: {name}")
                    old = declaration.group(0)
                    unwind = f"#[kani::unwind({bound})]\n"
                    new = {
                        "missing_attribute": old.replace(unwind, "", 1),
                        "missing_proof": old.replace("#[kani::proof]\n", "", 1),
                        "duplicate_attribute": old.replace(unwind, unwind + unwind, 1),
                        "zero_attribute": old.replace(
                            unwind, "#[kani::unwind(0)]\n", 1
                        ),
                    }[mutation]
                    replace_once(trust_path, old, new)
                    require_failure(
                        invoke(source, multi_manifest, public_manifest),
                        "invalid trust source declaration",
                        "kani::unwind"
                        if mutation in {"duplicate_attribute", "zero_attribute"}
                        else "source unwind declaration",
                    )
            reset()
            name = names[0]
            document = tomllib.loads(multi_manifest.read_text())
            row = next(row for row in document["harness"] if row["harness"] == name)
            old_bound = row["default_unwind"]
            row["default_unwind"] += 1
            replace_once(
                work / f"{crate}.rs",
                f"#[kani::unwind({old_bound})]\npub fn {name}()",
                f"#[kani::unwind({row['default_unwind']})]\npub fn {name}()",
            )
            write_toml(multi_manifest, document)
            result = invoke(source, multi_manifest, public_manifest)
            if result.returncode:
                raise AssertionError(
                    "coordinated fixture bound rejected:\n" + result.stderr
                )

        receipt = "public_sign_receipt_accepts_matching_kernel_key"
        for name in (
            "public_weights_hash_of_determinism_and_shape",
            "public_model_card_require_live_fail_closed",
            "public_weights_error_urn_is_stable",
            "public_model_card_new_pins_schema_version",
            "public_expect_report_data_determinism_and_binding",
        ):
            reset()
            head, tail = multi_manifest.read_text().split(f'harness = "{name}"', 1)
            tail = tail.replace("require_cover = true", "require_cover = false", 1)
            multi_manifest.write_text(head + f'harness = "{name}"' + tail)
            require_failure(
                invoke(source, multi_manifest, public_manifest),
                "disabled trust cover",
                "checked reachable PR enrollment",
            )

        for field, message in (
            ("unwinding_checks", "proof must enable unwinding checks"),
            ("require_cover", "proof must require a reachable witness"),
        ):
            reset()
            text = multi_manifest.read_text()
            head, tail = text.split(f'harness = "{receipt}"', 1)
            tail = tail.replace(f"{field} = true", f"{field} = false", 1)
            multi_manifest.write_text(head + f'harness = "{receipt}"' + tail)
            require_failure(
                invoke(source, multi_manifest, public_manifest),
                f"disabled receipt {field}",
                message,
            )

        reset()
        replace_once(
            source,
            f"#[kani::unwind(8)]\npub fn {receipt}()",
            f"#[kani::unwind(9)]\npub fn {receipt}()",
        )
        require_failure(
            invoke(source, multi_manifest, public_manifest),
            "ordinary loop bound drift",
            "ordinary bound 8",
        )

        reset()
        replace_once(public_manifest, f"{receipt} = 66", f"{receipt} = 8")
        require_failure(
            invoke(source, multi_manifest, public_manifest),
            "truncated key comparison",
            "complete 65-byte contract",
        )

        reset()
        hash_receipt = "public_sign_receipt_accepts_matching_content_hash"
        replace_once(public_manifest, f"{hash_receipt} = 8", f"{hash_receipt} = 7")
        require_failure(
            invoke(source, multi_manifest, public_manifest),
            "key recursion profile drift",
            "checked key recursion bound 8",
        )

        reset()
        replace_once(
            source,
            f"#[kani::unwind(66)]\npub fn {hash_receipt}()",
            f"#[kani::unwind(8)]\npub fn {hash_receipt}()",
        )
        require_failure(
            invoke(source, multi_manifest, public_manifest),
            "hash loop bound drift",
            "loop bound 66",
        )

        reset()
        replace_once(public_manifest, "cover_required = [", "obsolete_covers = [")
        require_failure(
            invoke(source, multi_manifest, public_manifest),
            "removed public-core cover requirement",
            "required cover posture differs",
        )

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
            '  "verify_replay_fingerprint_uniqueness",\n  "verify_family_binding_preservation",',
            '  "verify_replay_fingerprint_uniqueness",',
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
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts/tests/run-kani-reachability.test.py"),
        ],
        cwd=REPO_ROOT,
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts/tests/run-kani-function-bound.test.py"),
        ],
        cwd=REPO_ROOT,
        check=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
