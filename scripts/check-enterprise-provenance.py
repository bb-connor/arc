#!/usr/bin/env python3

import argparse
import sys
import tomllib
from pathlib import Path


REVIEWED_COMMIT = "666303e5f3428f3b6e6b72f118c269a02388e0a4"
REVIEWED_REPOSITORY = "https://github.com/backbay-labs/clawdstrike"
REVIEWED_SOURCE_BLOBS = {
    "crates/libs/clawdstrike-broker-protocol/src/lib.rs": "f0a1db48826f7a11bd3a8a741f93fd7f106e12fa",
    "crates/services/clawdstrike-brokerd/src/capability.rs": "3e0461594f4dbb85c640e91ab42cd14c93ba04d8",
    "crates/services/clawdstrike-brokerd/src/provider/generic_https.rs": "95f76e68053b12438bad1943cb030c55865c8f89",
    "crates/libs/clawdstrike/src/pkg/merkle.rs": "8cd306a1b4b589687b003ccc153ad71cd87af891",
    "crates/services/clawdstrike-registry/src/keys.rs": "2d64c39aaa1e6dbf83dc9e54e9e78ea482df963e",
    "crates/services/clawdstrike-registry/src/bin/audit-monitor.rs": "dcdbf352603ff55f1887b38bc4ca292bcd3a1008",
    "crates/libs/clawdstrike/src/sandbox/capability_builder.rs": "97ae47a40eabb8b8ae35169bf44a0298652cf983",
    "crates/libs/clawdstrike/src/sandbox/preflight.rs": "5abe9620cda286b58ef933a201afe86704050bd7",
    "crates/services/hush-cli/src/sandbox_nono.rs": "ae5bc38c7b00e21b6d6b9cfc4dfa02e0c3e50f23",
    "crates/services/hush-cli/src/supervised_exec.rs": "8a2b8b8cad3ff35c78daea86594cc766c6d57cfe",
    "infra/vendor/nono/": "241cac3a3f59fb1d60ec8c460bbd5238bc693055",
}
REQUIRED_SOURCES = set(REVIEWED_SOURCE_BLOBS)
ALLOWED_REUSE = {"concept", "test_shape", "no_use"}


def load_record(root: Path) -> dict:
    record = root / "third_party/provenance/clawdstrike-enterprise-hardening.toml"
    if not record.is_file():
        raise ValueError(f"enterprise provenance record is missing: {record}")
    with record.open("rb") as source:
        return tomllib.load(source)


def validate(root: Path, data: dict) -> list[str]:
    errors = []
    if data.get("schema") != "chio.enterprise-provenance.v1":
        errors.append("unsupported enterprise provenance schema")
    if data.get("source_commit") != REVIEWED_COMMIT:
        errors.append("source_commit does not match the reviewed commit")
    if data.get("source_repository") != REVIEWED_REPOSITORY:
        errors.append("source_repository does not match the reviewed repository")
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
        source_blob = entry.get("source_blob")
        if source_blob != REVIEWED_SOURCE_BLOBS.get(source_path):
            errors.append(f"{source_path}: source blob does not match the reviewed commit")
        if reuse not in ALLOWED_REUSE:
            errors.append(f"{source_path}: invalid reuse class")
        if copied is not False:
            any_copied = True
            errors.append(f"{source_path}: copied source is not approved")
        if not isinstance(destinations, list):
            errors.append(f"{source_path}: destinations must be an array")
        elif reuse != "no_use" and not destinations:
            errors.append(f"{source_path}: behavioral reuse requires a destination")
        elif reuse == "no_use" and destinations:
            errors.append(f"{source_path}: unused source must not name a destination")
        else:
            string_destinations = [
                destination for destination in destinations if isinstance(destination, str)
            ]
            if len(string_destinations) != len(set(string_destinations)):
                errors.append(f"{source_path}: destination inventory contains duplicates")
            for destination in destinations:
                if not isinstance(destination, str) or not destination:
                    errors.append(f"{source_path}: destination path is invalid")
                    continue
                relative = Path(destination)
                candidate = (root / relative).resolve()
                if relative.is_absolute() or root not in candidate.parents:
                    errors.append(f"{source_path}: destination escapes the repository")
                elif not candidate.is_file():
                    errors.append(f"{source_path}: destination does not exist: {destination}")
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
    errors = validate(args.root.resolve(), data)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("enterprise provenance check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
