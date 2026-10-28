# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9040b11ea385ff84e98e4063d81426678eceeb5a4d55e2f86191e7f0064502af
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChioFindingCurrentListingAssertionSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    generated_at: int
    listing_envelope_sha256: str
    listing_id: str
    max_age_secs: int
    namespace: str
    pricing_hint_envelope_sha256: str
    registry_operator_id: str
    schema_: Literal["chio.finding.current-listing-assertion.v1"] = Field(
        ..., alias="schema"
    )
    valid_until: int
