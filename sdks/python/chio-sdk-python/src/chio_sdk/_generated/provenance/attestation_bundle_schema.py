# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: addbe60437bb0258103fb68da7ee1ee5c1d4fade2ca6aab98f2d5ddc89f0b7e1
#
# Manual edits will be overwritten by the next regeneration; the
# M01.P3.T5 spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class EvidenceClass(Enum):
    """
    Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314), which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.
    """

    asserted = "asserted"
    observed = "observed"
    verified = "verified"


class Tier(Enum):
    """
    Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240).
    """

    none = "none"
    basic = "basic"
    attested = "attested"
    verified = "verified"


class Statement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: constr(min_length=1) = Field(
        ...,
        alias="schema",
        description="Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).",
    )
    verifier: constr(min_length=1) = Field(
        ...,
        description="Attestation verifier or relying party that accepted the evidence.",
    )
    tier: Tier = Field(
        ...,
        description="Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240).",
    )
    issued_at: conint(ge=0) = Field(
        ..., description="Unix timestamp (seconds) when this attestation was issued."
    )
    expires_at: conint(ge=0) = Field(
        ...,
        description="Unix timestamp (seconds) when this attestation expires. Bundle assembly fails closed when `assembledAt < issued_at` or `assembledAt >= expires_at`.",
    )
    evidence_sha256: constr(min_length=1) = Field(
        ...,
        description="Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.",
    )
    runtime_identity: constr(min_length=1) | None = Field(
        None,
        description="Optional runtime or workload identifier associated with the evidence.",
    )


class ChioProvenanceAttestationBundle(BaseModel):
    """
    One bundle of corroborating runtime attestation evidence statements that anchor a governed call-chain context to a verified runtime. The bundle names the `chainId` it binds to (matching `provenance/context.schema.json`), the canonical evidence-class that Chio resolved across the bundle as a whole, the unix-second `assembledAt` timestamp at which the bundle was assembled, and the ordered list of normalized runtime attestation evidence statements inside `statements`. Each statement mirrors the `RuntimeAttestationEvidence` shape in `crates/chio-core-types/src/capability.rs` (lines 484-507) and is identical in structure to `chio-wire/v1/trust-control/attestation.schema.json`; this schema references that family by inlining the same required field set rather than by `$ref` until the codegen pipeline lands in M01 phase 3. NOTE: there is no live `AttestationBundle` Rust struct on this branch; the bundle is drafted from `.planning/trajectory/01-spec-codegen-conformance.md` (Cross-doc references) plus the M09 supply-chain attestation milestone, which consumes this shape in its phase 3 attestation-verify path. The dedicated Rust struct is expected to land alongside M09 P3 and the schema will be re-pinned to that serde shape at that time. Field names are camelCase to match the convention used by the `GovernedCallChainContext` shape that this bundle binds to (`crates/chio-core-types/src/capability.rs` lines 952-967, `serde(rename_all = camelCase)`).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    chainId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the governed call chain this bundle attests. Matches the `chainId` carried by `provenance/context.schema.json`.",
    )
    evidenceClass: EvidenceClass = Field(
        ...,
        description="Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314), which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.",
    )
    assembledAt: conint(ge=0) = Field(
        ...,
        description="Unix timestamp (seconds) at which the bundle was assembled. Used to bound bundle freshness and to establish ordering with respect to receipts emitted from the same kernel.",
    )
    statements: list[Statement] = Field(
        ...,
        description="Ordered list of normalized runtime attestation evidence statements. Each statement is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json` and mirrors `RuntimeAttestationEvidence`. The struct does not carry `serde(rename_all)`, so per-statement field names are snake_case.",
        min_length=1,
    )
    issuer: constr(min_length=1) | None = Field(
        None,
        description="Optional identifier of the bundle assembler (kernel, gateway, or trust-control authority). Omitted when the bundle is locally assembled by the receiving kernel.",
    )
