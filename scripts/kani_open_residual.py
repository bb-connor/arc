"""The single owner-approved unfinished proof, never a successful proof result."""

from __future__ import annotations

from typing import Any

ATTESTATION = (
    "chio-attest-verify",
    "public_expect_report_data_determinism_and_binding",
)
FOLLOWUP = "KANI-ATTEST-DECOMP"


def validate_open_residuals(
    entries: list[dict[str, Any]], *, require_expected: bool = False
) -> set[tuple[str, str]]:
    """Refuse arbitrary exclusions and bind the one residual to its follow-up.

    Synthetic runner fixtures can omit the real attestation row. Repository
    enrollment checks require it, including its original execution contract.
    Closing this residual requires an explicit reviewed contract change.
    """
    residuals: set[tuple[str, str]] = set()
    for row in entries:
        if "open_residual" not in row:
            continue
        pair = (row.get("crate"), row.get("harness"))
        if (
            pair != ATTESTATION
            or row["open_residual"] != FOLLOWUP
            or pair in residuals
            or row.get("lane") != "pr"
            or row.get("unwinding_checks") is not True
            or row.get("require_cover") is not True
            or row.get("p256_encoder_bounds") is not True
            or row.get("features") != ["kani"]
        ):
            raise ValueError("invalid or duplicate open residual; only KANI-ATTEST-DECOMP is authorized")
        residuals.add(ATTESTATION)
    if require_expected and residuals != {ATTESTATION}:
        raise ValueError("missing open residual KANI-ATTEST-DECOMP; the proof is still unproved")
    return residuals
