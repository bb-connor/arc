# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b55a701e44e8cab56a79619656a773cbb3b9fd63c65594e997f7efc988bc178c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChioFindingBondStoreSnapshotSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    accepted_at: int
    allocation_id: str
    backing_envelope_sha256: str
    bond_ref: str
    finding_id: str
    live: bool
    observed_at: int
    schema_: Literal["chio.finding.bond-store-snapshot.v1"] = Field(..., alias="schema")
