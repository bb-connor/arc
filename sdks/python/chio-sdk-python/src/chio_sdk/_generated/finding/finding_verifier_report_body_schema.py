# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Facet(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    facet: str
    outcome: str
    reason: str


class FindingDelivery(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    accepted_bid_envelope_sha256: str
    authoritative_payment_operation_id: str
    digest_check: str
    finding_id: str
    listing_id: str
    media_type_check: str
    purchase_intent_id: str
    reservation_id: str
    schema_: str = Field(..., alias="schema")
    settlement_mode: str
    transform_profile: str
    venue_admission_envelope_sha256: str


class ChioFindingVerifierReportV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    backing_allocation_id: str | None = None
    evaluation_time: int
    facets: list[Facet]
    finding_artifact_sha256: str
    finding_delivery: FindingDelivery | None = None
    finding_delivery_receipt_id: str | None = None
    finding_id: str
    replay_recipe_input_sha256: str | None = None
    report_id: str
    resolved_evidence_bundle_sha256: str
    resolver_policy_sha256: str
    schema_: Literal["chio.finding.verifier-report.v1"] = Field(..., alias="schema")
    status_proof_input_sha256: str | None = None
    trust_root_snapshot_sha256: str
    trusted_time_input_sha256: str
    verifier_authority: str
    verifier_implementation_id: str
    verifier_key_epoch: int
    verifier_profile_envelope_sha256: str
    verifier_profile_id: str
