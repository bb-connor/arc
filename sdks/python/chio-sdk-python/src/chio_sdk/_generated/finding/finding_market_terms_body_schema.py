# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29e7de509b9e808e1385895b2caf534b995fb61bf99b87fab79bedc072f5a842
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class BaseFindingStake(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class MaximumSaleExposure(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class BackingRequirement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    base_finding_stake: BaseFindingStake
    collateral_policy: str
    maximum_sale_exposure: MaximumSaleExposure


class MaxBond(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class MinBond(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChallengeBondLimit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    guarantee_class: str
    max_bond: MaxBond
    min_bond: MinBond


class ChioFindingMarketTermsV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    appeal_window_secs: int
    audit_eligible: bool
    audit_epoch_length_secs: int
    backing_requirement: BackingRequirement
    challenge_bond_limits: list[ChallengeBondLimit]
    claim_window_secs: int
    decision_rule_refs: list[str]
    expires_at: int
    filing_window_secs: int
    finding_artifact_sha256: str
    finding_id: str
    issued_at: int
    listing_id: str
    payout_policy: str
    schema_: Literal["chio.finding.market-terms.v1"] = Field(..., alias="schema")
    seller: str
    terms_id: str
    verifier_profile_envelope_sha256: str
