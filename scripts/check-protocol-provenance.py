#!/usr/bin/env python3

import argparse
import re
import sys
import tomllib
from pathlib import Path


RECORD_PATH = Path("third_party/provenance/clawdstrike-protocol-primitives.toml")
REVIEWED_REPOSITORY = "https://github.com/backbay-labs/clawdstrike"
REVIEWED_COMMIT = "666303e5f3428f3b6e6b72f118c269a02388e0a4"
REVIEWED_NOTICE = (
    "ClawdStrike\n"
    "Copyright 2026 Backbay Industries\n"
    "\n"
    "This product includes software developed at Backbay Industries\n"
    "(https://backbay.io/).\n"
)
REVIEWED_INPUTS = {
    "crates/services/control-api/src/routes/policies/proposals.rs": {
        "source_blob": "6dba93d7cbcf53e5d7ec0610666207c7db5e5fae",
        "reuse": "concept",
        "destinations": {
            "crates/platform/chio-store-sqlite/src/approval_store_parts/part_02.rs"
        },
    },
    "crates/services/control-api/migrations/021_policy_proposals.sql": {
        "source_blob": "43f96ce443e22aa4c4dd6ee1638053e651bb4b67",
        "reuse": "concept",
        "destinations": {
            "crates/platform/chio-store-sqlite/src/approval_store_parts/part_01.rs"
        },
    },
    "crates/services/hushd/src/session/mod.rs": {
        "source_blob": "95f73d18a222a6b0f5e85383bb20b17bf02a8392",
        "reuse": "test_shape",
        "destinations": {"crates/platform/chio-store-sqlite/tests/approval_store.rs"},
    },
}
EXCLUDED_INPUTS = {
    "checkpoint_and_marketplace_witness_surfaces":
        "checkpoint and marketplace witness surfaces",
    "broker_constraints_and_posture_budgets":
        "broker constraints and posture budgets",
}
TOP_LEVEL_KEYS = {
    "schema",
    "source_repository",
    "source_commit",
    "license",
    "source_license_file",
    "source_notice_file",
    "source_notice",
    "notice_update_required",
    "reviewer",
    "reviewed_at",
    "inputs",
    "excluded_inputs",
    "excluded_spine",
}
INPUT_KEYS = {
    "source_path",
    "source_blob",
    "destinations",
    "reuse",
    "copied",
    "modifications",
}
EXCLUDED_INPUT_KEYS = {
    "category",
    "source_reference",
    "reuse",
    "destinations",
    "reason",
}
SPINE_KEYS = {
    "source_path",
    "named_upstream",
    "license_verified",
    "reuse",
    "copied",
    "destinations",
    "reason",
}
MARKER = "Adapted from " + "Clawdstrike"
MARKER_ROOTS = (
    Path("crates/core"),
    Path("crates/kernel"),
    Path("crates/platform/chio-store-sqlite"),
    Path("crates/protocol"),
    Path("crates/tooling/chio-conformance"),
)


def load_record(root: Path) -> dict:
    record = root / RECORD_PATH
    if not record.is_file():
        raise ValueError(f"protocol provenance record is missing: {record}")
    with record.open("rb") as source:
        return tomllib.load(source)


def validate_destination(root: Path, source_path: str, destination: object) -> list[str]:
    if not isinstance(destination, str) or not destination:
        return [f"{source_path}: destination path is invalid"]
    relative = Path(destination)
    if relative.is_absolute() or ".." in relative.parts:
        return [f"{source_path}: destination escapes the repository: {destination}"]
    candidate = root / relative
    resolved = candidate.resolve()
    if root != resolved and root not in resolved.parents:
        return [f"{source_path}: destination escapes the repository: {destination}"]
    if not candidate.is_file():
        return [f"{source_path}: destination does not exist: {destination}"]
    if candidate.is_symlink():
        return [f"{source_path}: destination must not be a symlink: {destination}"]
    return []


def protocol_markers(root: Path) -> tuple[set[str], list[str]]:
    marked = set()
    errors = []
    for relative_root in MARKER_ROOTS:
        marker_root = root / relative_root
        if not marker_root.is_dir():
            continue
        for candidate in sorted(marker_root.rglob("*.rs")):
            if not candidate.is_file() or candidate.is_symlink():
                continue
            relative = candidate.relative_to(root).as_posix()
            try:
                source = candidate.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                errors.append(
                    f"protocol provenance candidate is not valid UTF-8: {relative}"
                )
                continue
            except OSError as error:
                errors.append(
                    f"protocol provenance candidate could not be read: {relative}: {error}"
                )
                continue
            if MARKER in source:
                marked.add(relative)
    return marked, errors


def validate(root: Path, data: dict) -> list[str]:
    errors = []
    root = root.resolve()

    if set(data) != TOP_LEVEL_KEYS:
        errors.append("protocol provenance top-level field inventory mismatch")
    if data.get("schema") != "chio.protocol-primitives-provenance.v1":
        errors.append("unsupported protocol provenance schema")
    if data.get("source_repository") != REVIEWED_REPOSITORY:
        errors.append("source_repository does not match the reviewed repository")
    if data.get("source_commit") != REVIEWED_COMMIT:
        errors.append("source_commit does not match the reviewed commit")
    if data.get("license") != "Apache-2.0":
        errors.append("source license must be Apache-2.0")
    if data.get("source_license_file") != "LICENSE":
        errors.append("source license file must be LICENSE")
    if data.get("source_notice_file") != "NOTICE":
        errors.append("source NOTICE file must be NOTICE")
    if data.get("source_notice") != REVIEWED_NOTICE:
        errors.append("source NOTICE does not match the reviewed notice")
    if data.get("notice_update_required") is not False:
        errors.append("NOTICE disposition must remain false for non-copied reuse")
    if data.get("reviewer") != "Chio security review":
        errors.append("protocol provenance reviewer is incomplete")
    reviewed_at = data.get("reviewed_at")
    if not isinstance(reviewed_at, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", reviewed_at) is None:
        errors.append("protocol provenance review date is incomplete")

    inputs = data.get("inputs")
    if not isinstance(inputs, list):
        errors.append("protocol provenance inputs must be an array")
        inputs = []
    source_paths = [entry.get("source_path") for entry in inputs if isinstance(entry, dict)]
    if len(inputs) != len(REVIEWED_INPUTS) or len(source_paths) != len(set(source_paths)):
        errors.append("protocol source inventory contains missing or duplicate entries")
    if set(source_paths) != set(REVIEWED_INPUTS):
        errors.append("protocol source inventory mismatch")

    recorded_destinations = set()
    for entry in inputs:
        if not isinstance(entry, dict):
            errors.append("protocol source entry must be a table")
            continue
        source_path = entry.get("source_path", "<missing>")
        if set(entry) != INPUT_KEYS:
            errors.append(f"{source_path}: source field inventory mismatch")
        expected = REVIEWED_INPUTS.get(source_path)
        if expected is None:
            errors.append(f"{source_path}: source is outside the reviewed inventory")
            expected = {"source_blob": None, "reuse": None, "destinations": set()}
        if entry.get("source_blob") != expected["source_blob"]:
            errors.append(f"{source_path}: source blob does not match the reviewed commit")
        if entry.get("reuse") != expected["reuse"]:
            errors.append(f"{source_path}: reuse class does not match the reviewed boundary")
        if entry.get("copied") is not False:
            errors.append(f"{source_path}: copied source is not approved")
        modifications = entry.get("modifications")
        if not isinstance(modifications, str) or not modifications.strip():
            errors.append(f"{source_path}: modification boundary is missing")

        destinations = entry.get("destinations")
        if not isinstance(destinations, list):
            errors.append(f"{source_path}: destinations must be an array")
            continue
        string_destinations = [item for item in destinations if isinstance(item, str)]
        if len(string_destinations) != len(destinations):
            errors.append(f"{source_path}: destination path is invalid")
        if len(string_destinations) != len(set(string_destinations)):
            errors.append(f"{source_path}: destination inventory contains duplicates")
        if set(string_destinations) != expected["destinations"]:
            errors.append(f"{source_path}: destination mapping does not match the reviewed boundary")
        for destination in destinations:
            errors.extend(validate_destination(root, source_path, destination))
            if isinstance(destination, str):
                if destination in recorded_destinations:
                    errors.append(f"{destination}: destination is assigned to multiple sources")
                recorded_destinations.add(destination)

    excluded_inputs = data.get("excluded_inputs")
    if not isinstance(excluded_inputs, list):
        errors.append("excluded protocol inputs must be an array")
        excluded_inputs = []
    categories = [
        entry.get("category") for entry in excluded_inputs if isinstance(entry, dict)
    ]
    if len(excluded_inputs) != len(EXCLUDED_INPUTS) or len(categories) != len(set(categories)):
        errors.append("excluded protocol input inventory contains missing or duplicate entries")
    if set(categories) != set(EXCLUDED_INPUTS):
        errors.append("excluded protocol input inventory mismatch")
    for entry in excluded_inputs:
        if not isinstance(entry, dict):
            errors.append("excluded protocol input must be a table")
            continue
        category = entry.get("category", "<missing>")
        if set(entry) != EXCLUDED_INPUT_KEYS:
            errors.append(f"{category}: excluded input field inventory mismatch")
        if entry.get("source_reference") != EXCLUDED_INPUTS.get(category):
            errors.append(f"{category}: excluded source reference mismatch")
        if entry.get("reuse") != "no_use" or entry.get("destinations") != []:
            errors.append(f"{category}: unresolved input must remain no-use with no destinations")
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"{category}: exclusion reason is missing")

    excluded_spine = data.get("excluded_spine")
    if not isinstance(excluded_spine, dict):
        errors.append("Spine and AegisNet exclusion is missing")
        excluded_spine = {}
    if set(excluded_spine) != SPINE_KEYS:
        errors.append("Spine and AegisNet exclusion field inventory mismatch")
    if (
        excluded_spine.get("source_path") != "crates/libs/spine/"
        or excluded_spine.get("named_upstream") != "AegisNet"
        or excluded_spine.get("license_verified") is not False
        or excluded_spine.get("reuse") != "no_use"
        or excluded_spine.get("copied") is not False
        or excluded_spine.get("destinations") != []
    ):
        errors.append("Spine and AegisNet exclusion is incomplete")
    spine_reason = excluded_spine.get("reason")
    if not isinstance(spine_reason, str) or not spine_reason.strip():
        errors.append("Spine and AegisNet exclusion reason is missing")

    marked_destinations, marker_errors = protocol_markers(root)
    errors.extend(marker_errors)
    unrecorded_markers = marked_destinations - recorded_destinations
    for marker_path in sorted(unrecorded_markers):
        errors.append(f"protocol Clawdstrike marker is not recorded: {marker_path}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        data = load_record(root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(error, file=sys.stderr)
        return 1
    errors = validate(root, data)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("protocol provenance check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
