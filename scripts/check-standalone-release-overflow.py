#!/usr/bin/env python3
"""Exercise native overflow trapping with each selected shipping profile.

The probe isolates Cargo profile behavior without building the product dependency
closure. Product artifact and platform qualification remain separate gates.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PROFILE = re.compile(r"(?m)^\[profile\.(?P<name>[^\]\r\n]+)\]\s*\n(?:(?!^\[).*(?:\n|$))*")


@dataclass(frozen=True)
class ShippingProfile:
    manifest: Path
    profile: str
    package: str
    working_directory: Path


# Docker relocates its selected manifest and repository .cargo directory into
# /workspace. Probe that configuration context from ROOT, not deploy/docker.
# The proof-room and sidecar stages use the actual repository workspace.
SHIPPING_PROFILES = (
    ShippingProfile(ROOT / "sdks/lambda/chio-lambda-extension/Cargo.toml", "release",
                    "chio-lambda-extension", ROOT / "sdks/lambda/chio-lambda-extension"),
    ShippingProfile(ROOT / "sdks/rust/chio-guard-sdk-compat/Cargo.toml", "release",
                    "chio-guard-sdk-compat", ROOT / "sdks/rust/chio-guard-sdk-compat"),
    ShippingProfile(ROOT / "deploy/docker/chio-workspace/Cargo.toml", "docker-release",
                    "chio-cli", ROOT),
    ShippingProfile(ROOT / "Cargo.toml", "release", "chio-proof-room", ROOT),
    ShippingProfile(ROOT / "Cargo.toml", "docker-release", "chio-cli", ROOT),
)


def active_profiles(profiles: dict, selected: str) -> set[str]:
    active = set()
    profile = selected
    while profile is not None:
        if not isinstance(profile, str) or profile in active or len(active) >= 16:
            raise ValueError("shipping profile inheritance is invalid")
        active.add(profile)
        table = profiles.get(profile, {})
        if not isinstance(table, dict):
            raise ValueError("shipping profile must be a table")
        profile = table.get("inherits")
    return active


def refuse_profile_overrides(profiles: dict, active: set[str], source: Path) -> None:
    for name in active:
        table = profiles.get(name, {})
        if not isinstance(table, dict):
            raise ValueError(f"{source}: shipping profile must be a table")
        if "package" in table or "build-override" in table:
            raise ValueError(f"{source}: qualify profile overrides explicitly before shipping")


def merge_profile_tables(base: dict, overlay: dict) -> dict:
    """Cargo profiles use recursively merged tables and scalar precedence."""
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_profile_tables(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def profile_tables(value: dict, source: Path) -> dict:
    profiles = value.get("profile", {})
    if not isinstance(profiles, dict):
        raise ValueError(f"{source}: shipping profiles must be a table")
    return profiles


def cargo_configurations(working_directory: Path, environment: dict) -> list[Path]:
    cargo_home = Path(environment.get("CARGO_HOME", Path.home() / ".cargo"))
    if not cargo_home.is_absolute():
        cargo_home = working_directory / cargo_home
    directories = [cargo_home]
    directories.extend(path / ".cargo" for path in
                       reversed((working_directory, *working_directory.parents)))
    files = []
    for directory in directories:
        legacy = directory / "config"
        modern = directory / "config.toml"
        selected = legacy if legacy.is_file() else modern
        if selected.is_file() and selected not in files:
            files.append(selected)
    return files


def check_profile(shipping: ShippingProfile) -> None:
    manifest = shipping.manifest
    source = manifest.read_text()
    value = tomllib.loads(source)
    profiles = profile_tables(value, manifest)
    active = active_profiles(profiles, shipping.profile)
    if profiles.get(shipping.profile, {}).get("overflow-checks") is not True:
        raise ValueError(f"{manifest}: {shipping.profile} does not enable overflow checks")
    refuse_profile_overrides(profiles, active, manifest)
    environment = os.environ.copy()
    effective_profiles = profiles
    configurations = []
    for configuration in cargo_configurations(shipping.working_directory, environment):
        config = tomllib.loads(configuration.read_text())
        if "include" in config:
            raise ValueError(f"{configuration}: qualify configuration includes before shipping")
        config_profiles = profile_tables(config, configuration)
        configurations.append((configuration, config_profiles))
        effective_profiles = merge_profile_tables(effective_profiles, config_profiles)
    # An inheritance override can activate a parent supplied by a different
    # config file. Inspect the merged chain and keep all original tables in
    # the native probe, including parents activated through environment.
    for name in effective_profiles:
        variable = "CARGO_PROFILE_" + name.upper().replace("-", "_") + "_INHERITS"
        if variable in environment:
            if not isinstance(effective_profiles[name], dict):
                raise ValueError("shipping profile must be a table")
            effective_profiles[name]["inherits"] = environment[variable]
    active.update(active_profiles(effective_profiles, shipping.profile))
    refuse_profile_overrides(profiles, active, manifest)
    for configuration, config_profiles in configurations:
        refuse_profile_overrides(config_profiles, active, configuration)
    sections = [match.group() for match in PROFILE.finditer(source)]
    if not sections:
        raise ValueError(f"{manifest}: shipping profile is unavailable")

    with tempfile.TemporaryDirectory(prefix="chio-standalone-overflow-") as temporary:
        work = Path(temporary)
        (work / "src").mkdir()
        (work / "src/main.rs").write_bytes(
            (ROOT / "crates/tooling/chio-profile-probe/src/main.rs").read_bytes()
        )
        (work / "Cargo.toml").write_text(
            '[package]\nname=' + json.dumps(shipping.package) + '\nversion="0.0.0"\n'
            'edition="2021"\n[workspace]\n' + ''.join(sections)
        )
        (work / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = ' + json.dumps(shipping.package)
            + '\nversion = "0.0.0"\n'
        )
        environment["CARGO_TARGET_DIR"] = str(work / "target")
        built = subprocess.run(
            ["cargo", "build", "--offline", "--locked", "--quiet", "--profile", shipping.profile,
             "--manifest-path", str(work / "Cargo.toml")],
            cwd=shipping.working_directory,
            env=environment, capture_output=True, text=True, timeout=180,
        )
        if built.returncode != 0:
            detail = ascii(built.stderr[:8192])
            raise ValueError(f"{manifest}: profile probe build failed: {detail}")
        probe = subprocess.run(
            [str(work / "target" / shipping.profile / shipping.package), "0", "1"],
            capture_output=True, text=True, timeout=10,
        )
        if probe.returncode == 0 or "attempt to subtract with overflow" not in probe.stderr:
            raise ValueError(f"{manifest}: shipping profile or environment disabled overflow trapping")
    print(f"shipping overflow: {manifest} [{shipping.profile}] {shipping.package} "
          "traps budget subtraction below zero")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", action="append", type=Path)
    parser.add_argument("--profile", default="release", help="Profile for an explicit --manifest probe")
    args = parser.parse_args()
    if not args.manifest and args.profile != "release":
        parser.error("--profile requires an explicit --manifest")
    try:
        shipping = SHIPPING_PROFILES
        if args.manifest:
            shipping = []
            for manifest in args.manifest:
                manifest = manifest.resolve()
                value = tomllib.loads(manifest.read_text())
                package = value.get("package", {}).get("name", "chio-profile-probe")
                shipping.append(ShippingProfile(manifest, args.profile, package, manifest.parent))
        for profile in shipping:
            check_profile(profile)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"standalone release overflow refused: {ascii(str(error))}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
