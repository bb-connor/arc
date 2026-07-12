#!/usr/bin/env python3

import argparse
import sys
import tomllib
from pathlib import Path


REQUIRED_FEATURES = {
    "landlock",
    "seccomp_filter",
    "openat2",
    "execveat",
    "memfd_seals",
    "o_path",
    "pidfd",
    "ptrace_traceexec",
}
NONO_PIN = {
    "name": "nono",
    "version": "0.53.0",
    "source": "registry+https://github.com/rust-lang/crates.io-index",
    "repository": "https://github.com/always-further/nono",
    "tag": "v0.53.0",
    "commit": "c4b25b827330640cb95f85809d88d977191b42e7",
    "checksum": "ae7eb523cc2036e9ad6527411c3da5dc2172dc454cc3447a03b910420a39bfee",
    "license": "Apache-2.0",
}
SECCOMPILER_PIN = {
    "name": "seccompiler",
    "version": "0.5.0",
    "source": "registry+https://github.com/rust-lang/crates.io-index",
    "repository": "https://github.com/rust-vmm/seccompiler",
    "tag": "v0.5.0",
    "commit": "c3cf77d65815037931ae5bc2fca010713defdc8c",
    "checksum": "a4ae55de56877481d112a559bbc12667635fdaf5e005712fd4e2b2fa50ffc884",
    "license": "Apache-2.0 OR BSD-3-Clause",
}


def load_record(root: Path) -> dict:
    path = root / "third_party/provenance/linux-enforcement-stack.toml"
    if not path.is_file():
        raise ValueError(f"linux enforcement stack record is missing: {path}")
    with path.open("rb") as source:
        return tomllib.load(source)


def validate_pin(actual: object, expected: dict[str, str], label: str) -> list[str]:
    if not isinstance(actual, dict):
        return [f"{label} pin is missing"]
    if any(actual.get(key) != value for key, value in expected.items()):
        return [f"{label} pin does not match the reviewed source"]
    return []


def validate(data: dict) -> list[str]:
    errors = []
    if data.get("schema") != "chio.linux-enforcement-stack.v1":
        errors.append("unsupported linux enforcement stack schema")
    if not data.get("reviewed_at") or not data.get("reviewer"):
        errors.append("review record is incomplete")
    if data.get("minimum_linux") != "6.7" or data.get("minimum_landlock_abi") != 4:
        errors.append("minimum Linux or Landlock ABI does not match the reviewed baseline")
    if data.get("supported_architectures") != ["x86_64"]:
        errors.append("supported architecture set does not match the reviewed profiles")
    if set(data.get("required_kernel_features", [])) != REQUIRED_FEATURES:
        errors.append("required kernel feature inventory mismatch")

    nono = data.get("nono")
    errors.extend(validate_pin(nono, NONO_PIN, "nono"))
    if isinstance(nono, dict):
        if nono.get("default_network") != "blocked":
            errors.append("nono capability construction must start with network blocked")
        if nono.get("partially_enforced") != "reject":
            errors.append("partial Landlock enforcement must be rejected")
        if nono.get("caller_owned_path_fds") is not True:
            errors.append("Landlock rules must consume caller-owned path descriptors")
        if nono.get("patch_required") is not True:
            errors.append("the reviewed nono release requires a documented patch")

    seccompiler = data.get("seccompiler")
    errors.extend(validate_pin(seccompiler, SECCOMPILER_PIN, "seccompiler"))
    if isinstance(seccompiler, dict):
        if seccompiler.get("production_default_action") != "kill_process":
            errors.append("production seccomp must default to kill_process")
        if seccompiler.get("independent_from_nono_notify") is not True:
            errors.append("seccomp allowlisting must be independent from nono notification")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        data = load_record(args.root.resolve())
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(error, file=sys.stderr)
        return 1
    errors = validate(data)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("linux enforcement stack check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
