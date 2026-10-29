# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7c51d7910f0345879134e0bf5bbb042abd7b8dbfdcd23700753b77f6814a0f36
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class FreshnessWindow(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    valid_from: str
    valid_until: str


class ProviderCandidate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    availability_ref: str
    excluded: bool
    jurisdiction_ref: str
    pricing_surface_ref: str
    provider_passport_ref: str
    service_manifest_ref: str
    subject: str


class ChioCommerceProviderDiscoverySnapshotV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    discovery_authority_ref: str
    freshness_window: FreshnessWindow
    id: str
    issued_at: str
    market_scope: str
    order_id: str
    order_intent_ref: str
    passport_id: str
    provider_candidates: list[ProviderCandidate]
    schema_: Literal["chio.commerce.provider-discovery-snapshot.v1"] = Field(
        ..., alias="schema"
    )
