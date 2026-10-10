#!/usr/bin/env python3
"""Check the boundary between concrete SHA checks and unproved noncollision."""

from __future__ import annotations

import argparse
import hashlib
import sys

from kani_open_residual import validate_open_residuals
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

EXPECTED = {
    "chio-weights": (
        "public_weights_hash_of_determinism_and_shape",
        "public_weights_hash_of_determinism_and_tampering",
    ),
    "chio-attest-verify": (
        "public_expect_report_data_determinism_and_binding",
        "public_expect_report_data_determinism_under_input_change",
    ),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate(root: Path) -> None:
    def load(rel):
        return tomllib.loads((root / rel).read_text())

    scope = load("formal/rust-verification/crypto-proof-scope.toml")
    require(scope.get("schema") == "chio.crypto-proof-scope.v1", "unknown scope schema")
    rows = scope.get("obligation", [])
    require(
        len(rows) == len(EXPECTED) and {row["crate"] for row in rows} == set(EXPECTED),
        "missing or duplicate research obligation",
    )
    assumptions = load("formal/assumptions.toml")
    require(
        "ASSUME-SHA256" in assumptions["required_assumption_ids"],
        "SHA-256 assumption must remain required",
    )
    require(
        any(
            value.startswith("ASSUME-SHA256|audited_crypto|")
            for value in assumptions["assumptions"]
        ),
        "missing audited crypto assumption",
    )
    enrollments = load(".kani/harnesses.toml")["harness"]
    validate_open_residuals(enrollments, require_expected=True)
    for entry in enrollments:
        require(
            not any(
                feature.rsplit("/", 1)[-1] == "kani-research"
                for feature in entry.get("features", [])
            ),
            "research feature must not be enabled by mandatory enrollment",
        )
    for row in rows:
        crate = row["crate"]
        mandatory, original = EXPECTED[crate]
        require(
            row["status"] == "unproved" and row["assumption_id"] == "ASSUME-SHA256",
            f"{crate}: noncollision must remain an explicit unproved assumption",
        )
        require(
            (row["mandatory_harness"], row["research_harness"])
            == (mandatory, original),
            f"{crate}: unexpected harness classification",
        )
        required = [
            entry
            for entry in enrollments
            if entry["crate"] == crate and entry["harness"] == mandatory
        ]
        require(
            len(required) == 1,
            f"{crate}: mandatory concrete harness missing or duplicated",
        )
        require(
            not any(entry["harness"] == original for entry in enrollments),
            f"{crate}: unproved noncollision must not be mandatory",
        )
        require(
            "ASSUME-SHA256" in required[0].get("notes", ""),
            f"{crate}: enrollment must disclose assumption",
        )
        crate_root = root / f"crates/trust/{crate}"
        # Bind the complete mandatory module, including its input constructors.
        # Pinning only the harness declaration would let a constant fixture or
        # a narrowed domain silently replace the reviewed concrete obligation.
        mandatory_source = crate_root / "src/kani_public_harnesses.rs"
        require(
            hashlib.sha256(mandatory_source.read_bytes()).hexdigest()
            == row.get("mandatory_source_sha256"),
            f"{crate}: mandatory harness or fixture changed; review its domain and rebind its scope",
        )
        research = crate_root / "src/kani_crypto_research.rs"
        require(
            hashlib.sha256(research.read_bytes()).hexdigest() == row["source_sha256"],
            f"{crate}: original research obligation changed; review and rebind its scope",
        )
        require(
            f"pub fn {original}()" in research.read_text(),
            f"{crate}: original research harness absent",
        )
        library = (crate_root / "src/lib.rs").read_text()
        require(
            '#[cfg(all(kani, feature = "kani-research"))]\nmod kani_crypto_research;'
            in library,
            f"{crate}: research module must be opt-in",
        )
        features = tomllib.loads((crate_root / "Cargo.toml").read_text())["features"]
        # Research is selected explicitly by its feature name, never through
        # defaults, local aliases or qualified (including weak) dependency edges.
        # Forbidding incoming edges also prevents a cross-crate alias from hiding
        # a research edge behind an otherwise inactive local feature.
        require(
            not any(
                member.rsplit("/", 1)[-1] == "kani-research"
                for members in features.values()
                for member in members
            ),
            f"{crate}: research must not be enabled by another feature",
        )
        require(
            features.get("kani-research") == ["kani"],
            f"{crate}: invalid research feature",
        )
        require(
            {"sha2/force-soft", "chio-core-types/kani"}
            <= set(features.get("kani", [])),
            f"{crate}: concrete harness must retain real portable SHA-256",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    try:
        validate(args.root)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"crypto proof scope: {error}", file=sys.stderr)
        return 1
    print(
        "crypto proof scope: concrete gates, one OPEN/UNPROVED attestation residual and two unproved noncollision obligations are separate"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
