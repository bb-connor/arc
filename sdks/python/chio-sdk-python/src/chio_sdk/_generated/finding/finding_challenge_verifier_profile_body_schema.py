# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cdaf59925a71448dee294bc7dd11837a988bac5f39ad022834183bd6833707a0
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class BbsProjectionIssuer(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    issuer_fingerprint: str
    key_epoch: int
    key_hex: str
    registry_ref: str
    revocation_status_ref: str
    valid_from: int
    valid_until: int


class Signer(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_id: str
    key: str
    key_epoch: int
    revocation_status_ref: str
    rotation_policy_ref: str
    valid_from: int
    valid_until: int


class CheckpointLog(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    log_id: str
    signer: Signer


class FailedDeliveryAuthority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_id: str
    key: str
    key_epoch: int
    revocation_status_ref: str
    rotation_policy_ref: str
    valid_from: int
    valid_until: int


class PurchaseAuthority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_id: str
    key: str
    key_epoch: int
    revocation_status_ref: str
    rotation_policy_ref: str
    valid_from: int
    valid_until: int


class Policy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_id: str
    key: str
    key_epoch: int
    revocation_status_ref: str
    rotation_policy_ref: str
    valid_from: int
    valid_until: int


class ReceiptSigner(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    policy: Policy
    role: str


class ResourceCaps(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_evidence_receipts: int
    max_memory_bytes: int
    max_recipe_bytes: int
    max_runtime_secs: int


class VerifierReportSigner(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_id: str
    key: str
    key_epoch: int
    revocation_status_ref: str
    rotation_policy_ref: str
    valid_from: int
    valid_until: int


class ChioFindingChallengeVerifierProfileV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowed_predicates: list[str]
    allowed_runner_manifests: list[str]
    bbs_projection_issuer: BbsProjectionIssuer
    checkpoint_logs: list[CheckpointLog]
    expires_at: int
    failed_delivery_authority: FailedDeliveryAuthority
    governance_authority: str
    issued_at: int
    operator: str
    predicate_engine: str
    profile_id: str
    purchase_authority: PurchaseAuthority
    receipt_signers: list[ReceiptSigner]
    required_facets: list[str]
    required_receipt_semantics: str
    resolver_policy_ref: str
    resource_caps: ResourceCaps
    retention_policy_ref: str
    schema_: Literal["chio.finding.challenge-verifier-profile.v1"] = Field(
        ..., alias="schema"
    )
    verifier_report_signer: VerifierReportSigner
