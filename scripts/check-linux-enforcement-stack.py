#!/usr/bin/env python3

import argparse
import hashlib
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
LANDLOCK_PIN = {
    "name": "landlock",
    "version": "0.4.4",
    "source": "registry+https://github.com/rust-lang/crates.io-index",
    "repository": "https://github.com/landlock-lsm/rust-landlock",
    "tag": "v0.4.4",
    "commit": "89c56e2db04cf0a4d63e192e7b4371af516a1ccc",
    "checksum": "49fefd6652c57d68aaa32544a4c0e642929725bdc1fd929367cdeb673ab81088",
    "license": "MIT OR Apache-2.0",
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
PATCH_CHANGES = {
    "return observed Landlock ABI and RulesetStatus",
    "reject partially enforced filesystem and network rules",
    "construct PathBeneath rules from caller-owned descriptors",
    "retain caller ownership through ruleset application",
    "grant directory listing without granting descendant file reads",
    "handle every filesystem and network right known to the detected ABI",
}


def load_toml(path: Path) -> dict:
    if not path.is_file():
        raise ValueError(f"required TOML file is missing: {path}")
    with path.open("rb") as source:
        return tomllib.load(source)


def load_record(root: Path) -> dict:
    return load_toml(root / "third_party/provenance/linux-enforcement-stack.toml")


def validate_pin(actual: object, expected: dict[str, str], label: str) -> list[str]:
    if not isinstance(actual, dict):
        return [f"{label} pin is missing"]
    if any(actual.get(key) != value for key, value in expected.items()):
        return [f"{label} pin does not match the reviewed source"]
    return []


def read_text(path: Path, errors: list[str], label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        errors.append(f"{label} is missing: {path}")
        return ""


def read_linux_launcher(root: Path, errors: list[str]) -> str:
    launcher_root = root / "crates/security/chio-cage/src/launch"
    entrypoint = read_text(
        launcher_root / "linux.rs",
        errors,
        "chio-cage Linux launcher entrypoint",
    )
    part_paths = [
        launcher_root / "linux_parts/part_01.rs",
        launcher_root / "linux_parts/part_02.rs",
    ]
    section_paths = [
        launcher_root / "linux_parts/part_01_sections/bootstrap.inc",
        launcher_root / "linux_parts/part_01_sections/sandbox.inc",
    ]
    expected_entrypoint = "\n".join(
        f'include!("linux_parts/{path.name}");' for path in part_paths
    ) + "\n"
    if entrypoint and entrypoint != expected_entrypoint:
        errors.append("chio-cage Linux launcher module inventory is invalid")
    expected_part_01 = '''include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/launch/linux_parts/part_01_sections/bootstrap.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/launch/linux_parts/part_01_sections/sandbox.inc"
));
'''
    parts = [
        read_text(path, errors, f"chio-cage Linux launcher {path.name}")
        for path in part_paths
    ]
    if parts[0] and parts[0] != expected_part_01:
        errors.append("chio-cage Linux launcher part_01 section inventory is invalid")
    sections = [
        read_text(
            path,
            errors,
            f"chio-cage Linux launcher {path.relative_to(launcher_root)}",
        )
        for path in section_paths
    ]
    expected_files = {path.relative_to(launcher_root) for path in [*part_paths, *section_paths]}
    actual_files = {
        path.relative_to(launcher_root)
        for path in (launcher_root / "linux_parts").rglob("*")
        if path.is_file()
    }
    if actual_files != expected_files:
        errors.append("chio-cage Linux launcher file inventory is invalid")
    return "\n".join([entrypoint, *parts, *sections])


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_record(data: dict) -> list[str]:
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
        patch = nono.get("patch")
        if not isinstance(patch, dict):
            errors.append("the required nono wrapper patch record is missing")
        else:
            if (
                patch.get("directory") != "third_party/nono-chio"
                or patch.get("kind") != "wrapper"
                or patch.get("package_name") != "nono-chio"
                or patch.get("version") != "0.53.0-chio.2"
                or patch.get("status") != "required"
            ):
                errors.append("the nono wrapper patch identity is invalid")
            if set(patch.get("changes", [])) != PATCH_CHANGES:
                errors.append("the nono wrapper patch inventory is incomplete")
            digest = patch.get("source_sha256")
            if not isinstance(digest, str) or len(digest) != 64:
                errors.append("the nono wrapper source digest is invalid")

    errors.extend(validate_pin(data.get("landlock"), LANDLOCK_PIN, "landlock"))

    seccompiler = data.get("seccompiler")
    errors.extend(validate_pin(seccompiler, SECCOMPILER_PIN, "seccompiler"))
    if isinstance(seccompiler, dict):
        if seccompiler.get("production_default_action") != "kill_process":
            errors.append("production seccomp must default to kill_process")
        if seccompiler.get("independent_from_nono_notify") is not True:
            errors.append("seccomp allowlisting must be independent from nono notification")
    return errors


def validate_manifests(root: Path, errors: list[str]) -> None:
    try:
        cage = load_toml(root / "crates/security/chio-cage/Cargo.toml")
        wrapper = load_toml(root / "third_party/nono-chio/Cargo.toml")
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        errors.append(str(error))
        return

    linux = (
        cage.get("target", {})
        .get('cfg(target_os = "linux")', {})
        .get("dependencies", {})
    )
    nono_dependency = linux.get("nono-chio")
    if not isinstance(nono_dependency, dict) or nono_dependency.get("path") != "../../../third_party/nono-chio":
        errors.append("chio-cage must depend on the reviewed local nono-chio wrapper")
    if linux.get("seccompiler") != "=0.5.0":
        errors.append("chio-cage seccompiler dependency must be pinned to =0.5.0")
    if cage.get("features", {}).get("enforcement-mutants") != []:
        errors.append("the test-only enforcement-mutants feature is missing")

    package = wrapper.get("package", {})
    if package.get("name") != "nono-chio" or package.get("version") != "0.53.0-chio.2":
        errors.append("nono-chio wrapper package identity is invalid")
    dependencies = wrapper.get("dependencies", {})
    nono = dependencies.get("nono")
    if not isinstance(nono, dict) or nono.get("version") != "=0.53.0" or nono.get("default-features") is not False:
        errors.append("nono-chio must pin nono =0.53.0 with default features disabled")
    if dependencies.get("landlock") != "=0.4.4":
        errors.append("nono-chio must pin landlock =0.4.4")


def validate_sources(root: Path, data: dict, errors: list[str]) -> None:
    wrapper_root = root / "third_party/nono-chio"
    wrapper_source_path = wrapper_root / "src/lib.rs"
    wrapper_source = read_text(wrapper_source_path, errors, "nono-chio wrapper source")
    wrapper_readme = read_text(wrapper_root / "README.md", errors, "nono-chio README")
    wrapper_patches = read_text(wrapper_root / "PATCHES.md", errors, "nono-chio patch inventory")
    read_text(wrapper_root / "LICENSE-APACHE", errors, "nono-chio Apache license")
    notice = read_text(root / "NOTICE", errors, "repository NOTICE")
    if wrapper_source:
        expected_digest = data.get("nono", {}).get("patch", {}).get("source_sha256")
        if expected_digest != sha256(wrapper_source_path):
            errors.append("nono-chio wrapper source digest does not match provenance")
        for required in [
            "nono::CapabilitySet::new().block_network()",
            "BorrowedFd",
            "PathBeneath::new(grant.fd",
            "CompatLevel::HardRequirement",
            "RulesetStatus::PartiallyEnforced",
            "RulesetStatus::NotEnforced",
            "enforce_filesystem",
            "enforce_network_blocked",
            "AccessFs::from_all(kernel_abi)",
            "AccessNet::from_all(kernel_abi)",
            "PathAccess::ReadDirectory",
        ]:
            if required not in wrapper_source:
                errors.append(f"nono-chio source is missing required enforcement token: {required}")
        if "PathFd::new" in wrapper_source:
            errors.append("nono-chio must not reopen a caller-validated pathname")
    if (
        "Luke Hinds" not in wrapper_patches
        or "always-further/nono" not in wrapper_patches
        or NONO_PIN["commit"] not in wrapper_patches
    ):
        errors.append("nono-chio patch inventory is missing upstream attribution")
    for required in [
        "nono 0.53.0",
        "Luke Hinds",
        "https://github.com/always-further/nono",
        NONO_PIN["commit"],
        "Apache License, Version 2.0",
    ]:
        if required not in notice:
            errors.append(f"repository NOTICE is missing nono attribution: {required}")
    if "caller-owned" not in wrapper_readme or "FullyEnforced" not in wrapper_readme:
        errors.append("nono-chio README does not state the reviewed enforcement contract")

    linux_source = read_linux_launcher(root, errors)
    for required in [
        "nono_chio::CapabilitySet::new()",
        "BorrowedFd::borrow_raw",
        "seccompiler::SeccompFilter::new",
        "seccompiler::apply_filter",
        "SeccompAction::KillProcess",
        "landlock_filesystem_status",
        "landlock_network_status",
        "SeccompEnforcementStatus::FullyEnforced",
        "duplicate_helper_exec_fd",
        'format!("/proc/self/fd/{}", helper_exec_fd.as_raw_fd())',
        "Command::new(helper_exec_path)",
    ]:
        if required not in linux_source:
            errors.append(f"Linux launcher is missing required enforcement token: {required}")
    if "Command::new(helper_path)" in linux_source:
        errors.append("Linux launcher reopens the admitted helper by pathname")
    for forbidden in ["SYS_landlock", "sock_fprog", "SECCOMP_SET_MODE_FILTER"]:
        if forbidden in linux_source:
            errors.append(f"Linux launcher bypasses the reviewed compiler or adapter: {forbidden}")

    cage_lib = read_text(root / "crates/security/chio-cage/src/lib.rs", errors, "chio-cage library")
    if 'all(feature = "enforcement-mutants", not(debug_assertions))' not in cage_lib:
        errors.append("release builds do not reject the test-only enforcement-mutants feature")
    cage_linux = read_text(
        root / "crates/security/chio-cage/src/linux.rs",
        errors,
        "chio-cage Linux admission",
    )
    for required in [
        "RuntimeArtifactRole::CageInitHelper",
        "PT_INTERP",
        "PT_DYNAMIC",
        "DT_NEEDED",
        "DT_RPATH",
        "DT_RUNPATH",
        "checked_elf_range",
    ]:
        if required not in cage_linux:
            errors.append(f"Linux admission is missing the static PIE contract: {required}")
    receipt_source = read_text(
        root / "crates/security/chio-cage/src/receipt.rs",
        errors,
        "chio-cage signed receipt adapter",
    )
    for required in [
        "ReceiptSigningHandle::from_content",
        "ChioReceipt::sign_with_backend_using_handle",
        "verify_signed_cage_receipt",
        "persist_signed_cage_receipt",
        "persist_signed_cage_receipt_with_trusted_key",
        "CageEnforcementState::FullyEnforced",
        "CageEnforcementState::Exited",
    ]:
        if required not in receipt_source:
            errors.append(f"signed cage receipt adapter is missing required token: {required}")
    linux_tests = read_text(
        root / "crates/security/chio-cage/tests/linux_enforcement.rs",
        errors,
        "chio-cage Linux enforcement tests",
    )
    for required in [
        "DisableLandlock",
        "PartialLandlock",
        "DisableSeccomp",
        "UnsealedPlan",
        "CorruptPlanDigest",
        "DropDescriptor",
        "MalformedStatus",
        "TraceBindingMismatch",
        "ExitBeforeExec",
        "CHIO_CAGE_TEST_CONNECT_IPV4",
        "CHIO_CAGE_TEST_BIND_IPV6",
        "CHIO_CAGE_TEST_UNDECLARED_EXEC",
        "CHIO_CAGE_TEST_DYNAMIC_RUNTIME",
        "CHIO_CAGE_TEST_DIRECTORY_HARD_LINK",
    ]:
        if required not in linux_tests:
            errors.append(f"Linux enforcement tests are missing required coverage: {required}")
    linux_runner = read_text(
        root / "crates/security/chio-cage/scripts/check-linux-enforcement.sh",
        errors,
        "chio-cage real Linux runner",
    )
    for required in [
        "Linux:x86_64",
        "cage_dynamic_probe.c",
        "CHIO_CAGE_TEST_DYNAMIC_RUNTIME",
        "CHIO_CAGE_TEST_HELPER",
        "target-feature=+crt-static",
        "relocation-model=pie",
        'readelf -hW "$static_helper"',
        'readelf -lW "$static_helper"',
        'readelf -dW "$static_helper"',
        "NEEDED|RPATH|RUNPATH",
    ]:
        if required not in linux_runner:
            errors.append(f"real Linux runner is missing required contract: {required}")
    if "Linux:aarch64" in linux_runner:
        errors.append("real Linux runner enables an architecture outside the reviewed set")


def find_locked_package(lock: dict, name: str, version: str) -> dict | None:
    for package in lock.get("package", []):
        if package.get("name") == name and package.get("version") == version:
            return package
    return None


def validate_lock(root: Path, errors: list[str]) -> None:
    try:
        lock = load_toml(root / "Cargo.lock")
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        errors.append(str(error))
        return
    for pin in [NONO_PIN, LANDLOCK_PIN, SECCOMPILER_PIN]:
        package = find_locked_package(lock, pin["name"], pin["version"])
        if package is None or package.get("source") != pin["source"] or package.get("checksum") != pin["checksum"]:
            errors.append(f"Cargo.lock does not contain the reviewed {pin['name']} pin")
    wrapper = find_locked_package(lock, "nono-chio", "0.53.0-chio.2")
    if wrapper is None or wrapper.get("source") is not None:
        errors.append("Cargo.lock does not contain the local nono-chio wrapper")


def validate(root: Path, data: dict, require_lock: bool) -> list[str]:
    errors = validate_record(data)
    validate_manifests(root, errors)
    validate_sources(root, data, errors)
    if require_lock:
        validate_lock(root, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument(
        "--require-lock",
        action="store_true",
        help="also require the reviewed packages and checksums in Cargo.lock",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        data = load_record(root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(error, file=sys.stderr)
        return 1
    errors = validate(root, data, args.require_lock)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("linux enforcement stack check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
