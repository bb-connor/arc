#!/usr/bin/env python3
"""Install and identify the narrowly repaired Kani 0.68.0 compiler.

Upstream PR 4819 corrects an obsolete intrinsic signature assertion. It does
not implement catch_unwind: the installation controls require reachable uses
to fail verification. Release assets, rustc, CBMC and proof options stay intact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

VERSION = "0.68.0"
REVISION = "0d2328a93f0e0ff66132d6bfa1a7d884877cf862"
UPSTREAM_FIX = "e47388fd566662202ce194818719c21ef25660ba"
CHARON_REVISION = "b250680abd40ff1aaa07081d0497dc2755ed112e"
TOOLCHAIN = "nightly-2026-08-21"
MARKER = "chio-compiler.json"
ORIGINAL_SIGNATURE = (
    '"catch_unwind" => {\n'
    "                assert_sig_matches!(sig, RigidTy::FnPtr(_), "
    "RigidTy::RawPtr(_, Mutability::Mut), RigidTy::FnPtr(_) "
    "=> RigidTy::Int(IntTy::I32));"
)
REPAIRED_SIGNATURE = ORIGINAL_SIGNATURE.replace(
    "RigidTy::Int(IntTy::I32)", "RigidTy::Bool"
)


def repair_intrinsics(source: str) -> str:
    if source.count(ORIGINAL_SIGNATURE) != 1:
        raise ValueError("Kani source differs from the reviewed intrinsic assertion")
    return source.replace(ORIGINAL_SIGNATURE, REPAIRED_SIGNATURE, 1)


def identity(bundle: Path) -> dict:
    compiler = bundle / "bin/kani-compiler"
    with compiler.open("rb") as stream:
        compiler_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "schema": "chio.kani-compiler.v1",
        "release": VERSION,
        "source_revision": REVISION,
        "upstream_fix": UPSTREAM_FIX,
        "compiler_sha256": compiler_sha256,
    }


def record_bundle(bundle: Path) -> None:
    (bundle / MARKER).write_text(json.dumps(identity(bundle), sort_keys=True) + "\n")


def check_bundle(bundle: Path) -> None:
    try:
        if json.loads((bundle / MARKER).read_text()) != identity(bundle):
            raise ValueError(
                "Kani compiler cache differs from its pinned source identity"
            )
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(
            "Kani compiler repair is absent; run scripts/kani-toolchain.py install"
        ) from error


def run(arguments: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, check=True, **kwargs)


def install_build_toolchain() -> None:
    # RUSTUP_TOOLCHAIN overrides the source's rust-toolchain.toml, including its
    # component installation. Provision the reviewed source's build requirements
    # explicitly; cargo kani setup installs only the release runtime.
    run(
        [
            "rustup",
            "toolchain",
            "install",
            TOOLCHAIN,
            "--profile",
            "minimal",
            "--component",
            "llvm-tools,rustc-dev,rust-src,rustfmt",
        ]
    )


def qualify_compiler(directory: Path) -> None:
    """Check success and unsupported-code rejection using the actual compiler."""
    cases = (
        ("valid", "let value: u8 = kani::any(); assert!(value <= u8::MAX);", True),
        (
            "unsupported",
            "let value = std::panic::catch_unwind(|| 42); assert!(value.is_ok());",
            False,
        ),
    )
    for name, body, success in cases:
        source = directory / f"{name}.rs"
        source.write_text(f"#[kani::proof]\nfn check() {{ {body} }}\n")
        result = subprocess.run(
            ["kani", str(source), "--harness", "check"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        print(result.stdout, end="")
        expected = (
            "VERIFICATION:- SUCCESSFUL"
            if success
            else "catch_unwind is not currently supported"
        )
        if (result.returncode == 0) != success or expected not in result.stdout:
            raise ValueError(f"Kani {name} compiler control failed")
        if "internal compiler error" in result.stdout:
            raise ValueError("Kani compiler control crashed")


def install(bundle: Path, work_directory: Path) -> None:
    try:
        check_bundle(bundle)
    except ValueError:
        pass
    else:
        with tempfile.TemporaryDirectory(
            prefix="kani-controls-", dir=work_directory
        ) as scratch:
            qualify_compiler(Path(scratch))
        return
    if not (bundle / "bin/kani-compiler").is_file():
        raise ValueError("Install kani-verifier 0.68.0 and run cargo kani setup first")
    install_build_toolchain()
    with tempfile.TemporaryDirectory(
        prefix="kani-source-", dir=work_directory
    ) as scratch:
        source = Path(scratch) / "source"
        run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                f"kani-{VERSION}",
                "https://github.com/model-checking/kani.git",
                str(source),
            ]
        )
        actual = run(
            ["git", "rev-parse", "HEAD"], cwd=source, capture_output=True, text=True
        ).stdout.strip()
        if actual != REVISION:
            raise ValueError(
                "Kani release tag no longer identifies the reviewed source"
            )
        run(
            ["git", "submodule", "update", "--init", "--depth", "1", "charon"],
            cwd=source,
        )
        actual = run(
            ["git", "rev-parse", "HEAD"],
            cwd=source / "charon",
            capture_output=True,
            text=True,
        ).stdout.strip()
        if actual != CHARON_REVISION:
            raise ValueError("Kani Charon source differs from the release pin")
        intrinsics = source / "kani-compiler/src/intrinsics.rs"
        intrinsics.write_text(repair_intrinsics(intrinsics.read_text()))
        target = work_directory / "compiler-target"
        environment = dict(
            os.environ,
            CARGO_TARGET_DIR=str(target),
            CARGO_INCREMENTAL="0",
            CARGO_PROFILE_DEV_DEBUG="0",
            RUSTUP_TOOLCHAIN=TOOLCHAIN,
        )
        # Caller build flags and toolchain overrides must not change the pinned
        # compiler build. The release source owns its cargo configuration.
        environment.pop("RUSTFLAGS", None)
        environment.pop("CARGO_ENCODED_RUSTFLAGS", None)
        run(
            ["cargo", "build", "--locked", "-p", "kani-compiler"],
            cwd=source,
            env=environment,
        )
        candidate = bundle / "bin/kani-compiler.chio-new"
        shutil.copy2(target / "debug/kani-compiler", candidate)
        candidate.replace(bundle / "bin/kani-compiler")
        qualify_compiler(Path(scratch))
        # An interrupted build or failed semantic control never writes acceptance.
        record_bundle(bundle)
    check_bundle(bundle)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "install"))
    parser.add_argument("--work-directory", type=Path)
    args = parser.parse_args()
    bundle = (
        Path(os.environ.get("KANI_HOME", Path.home() / ".kani")) / f"kani-{VERSION}"
    )
    try:
        if args.command == "check":
            check_bundle(bundle)
        else:
            work = (
                args.work_directory
                or Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
                / "chio-kani"
            )
            work = work.resolve()
            work.mkdir(parents=True, exist_ok=True)
            install(bundle, work)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Kani toolchain qualification failed: {error}\n")
    print(f"Kani {VERSION} compiler identity verified with upstream fix {UPSTREAM_FIX}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
