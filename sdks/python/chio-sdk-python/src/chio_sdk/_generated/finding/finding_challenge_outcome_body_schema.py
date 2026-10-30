# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DigestMismatch(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    committed_payload_sha256: str
    delivered_output_sha256: str
    realized_spend_units: int
    transform_profile: str


class EvidenceInvalid(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    challenged_receipt_ids: list[str]
    invalidity: str


class ReplayContradiction(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    observation_digests: list[str]
    predicate: str
    predicate_result: str
    recipe_sha256: str
    replay_run_id: str


class Facet(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    digest_mismatch: DigestMismatch | None = None
    evidence_invalid: EvidenceInvalid | None = None
    replay_contradiction: ReplayContradiction | None = None


class PenaltyAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class PenaltyCalculation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    base_finding_stake_units: int
    computed_exposure_units: int
    listing_required_amount_units: int
    live_allocated_collateral_units: int
    open_per_sale_encumbrance_units: int
    penalty_amount: PenaltyAmount


class ChioFindingChallengeOutcomeV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audit_epoch_envelope_sha256: str | None = None
    authorization: str
    backing_allocation_id: str
    challenge_envelope_sha256: str
    evaluated_at: int
    evaluator_authority_id: str
    evaluator_key: str
    evaluator_key_epoch: int
    evaluator_revocation_status_ref: str
    evaluator_valid_from: int
    evaluator_valid_until: int
    evidence_bundle_digest: str
    evidence_kind: str
    facet: Facet
    finding_id: str
    listing_id: str
    outcome_id: str
    penalty_calculation: PenaltyCalculation | None = None
    reason: str
    retry_deadline: int | None = None
    schema_: Literal["chio.finding.challenge-outcome.v1"] = Field(..., alias="schema")
    trigger_digest: str
    verdict: str
    verifier_profile_envelope_sha256: str
