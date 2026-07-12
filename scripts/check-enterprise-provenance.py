#!/usr/bin/env python3

import argparse
import sys
import tomllib
from pathlib import Path


REVIEWED_COMMIT = "666303e5f3428f3b6e6b72f118c269a02388e0a4"
REQUIRED_SOURCES = {
    "crates/libs/clawdstrike-broker-protocol/src/lib.rs",
    "crates/services/clawdstrike-brokerd/src/capability.rs",
    "crates/services/clawdstrike-brokerd/src/provider/generic_https.rs",
    "crates/libs/clawdstrike/src/pkg/merkle.rs",
    "crates/services/clawdstrike-registry/src/keys.rs",
    "crates/services/clawdstrike-registry/src/bin/audit-monitor.rs",
    "crates/libs/clawdstrike/src/sandbox/capability_builder.rs",
    "crates/libs/clawdstrike/src/sandbox/preflight.rs",
    "crates/services/hush-cli/src/sandbox_nono.rs",
    "crates/services/hush-cli/src/supervised_exec.rs",
    "infra/vendor/nono/",
}
ALLOWED_REUSE = {"concept", "test_shape", "no_use"}


def load_record(root: Path) -> dict:
    record = root / "third_party/provenance/clawdstrike-enterprise-hardening.toml"
    if not record.is_file():
        raise ValueError(f"enterprise provenance record is missing: {record}")
    with record.open("rb") as source:
        return tomllib.load(source)


def validate(data: dict) -> list[str]:
    errors = []
    if data.get("schema") != "chio.enterprise-provenance.v1":
        errors.append("unsupported enterprise provenance schema")
    if data.get("source_commit") != REVIEWED_COMMIT:
        errors.append("source_commit does not match the reviewed commit")
    if not data.get("source_repository"):
        errors.append("source_repository is missing")
    if data.get("license") != "Apache-2.0":
        errors.append("source license must be Apache-2.0")
    if "Backbay Industries" not in data.get("source_notice", ""):
        errors.append("source NOTICE attribution is incomplete")
    if not data.get("reviewer") or not data.get("reviewed_at"):
        errors.append("review record is incomplete")

    inputs = data.get("inputs", [])
    source_paths = [entry.get("source_path") for entry in inputs]
    if len(source_paths) != len(set(source_paths)) or set(source_paths) != REQUIRED_SOURCES:
        errors.append("source inventory mismatch")
    any_copied = False
    for entry in inputs:
        source_path = entry.get("source_path", "<missing>")
        reuse = entry.get("reuse")
        copied = entry.get("copied")
        destinations = entry.get("destinations")
        if reuse not in ALLOWED_REUSE:
            errors.append(f"{source_path}: invalid reuse class")
        if copied is not False:
            any_copied = True
            errors.append(f"{source_path}: copied source is not approved")
        if not isinstance(destinations, list):
            errors.append(f"{source_path}: destinations must be an array")
        elif reuse != "no_use" and not destinations:
            errors.append(f"{source_path}: behavioral reuse requires a destination")
        if not entry.get("modifications"):
            errors.append(f"{source_path}: modification boundary is missing")

    if bool(data.get("notice_update_required")) != any_copied:
        errors.append("NOTICE disposition does not match copied-source status")

    excluded = data.get("excluded_spine", {})
    if (
        excluded.get("source_path") != "crates/libs/spine/"
        or excluded.get("named_upstream") != "AegisNet"
        or excluded.get("license_verified") is not False
        or excluded.get("copied") is not False
    ):
        errors.append("Spine and AegisNet exclusion is incomplete")
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
    print("enterprise provenance check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
