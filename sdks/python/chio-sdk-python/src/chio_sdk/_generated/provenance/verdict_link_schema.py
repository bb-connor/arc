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


class Verdict(Enum):
    """
    Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.
    """

    allow = "allow"
    deny = "deny"
    cancel = "cancel"
    incomplete = "incomplete"


class EvidenceClass(Enum):
    """
    Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.
    """

    asserted = "asserted"
    observed = "observed"
    verified = "verified"


class ChioProvenanceVerdictLink(BaseModel):
    """
    One link binding a Chio policy verdict to the provenance graph. The link names the `verdict` decision that Chio's policy engine returned (`allow`, `deny`, `cancel`, `incomplete`), the `requestId` and optional `receiptId` the verdict applies to, and the `chainId` that ties the verdict back to a delegated call-chain context. Optional fields preserve the policy `reason` and `guard` when the verdict is not `allow` and the `evidenceClass` Chio resolved when the verdict was rendered. The verdict vocabulary mirrors the HTTP verdict tagged union in `spec/schemas/chio-http/v1/verdict.schema.json` and the per-step verdict family `StepVerdictKind` in `crates/chio-core-types/src/plan.rs` (lines 110-138). NOTE: there is no live `VerdictLink` Rust struct on this branch; the link is drafted as the wire form of the verdict-to-provenance edge that M07's tool-call fabric and the M01 receipt-record schema reference indirectly today. The dedicated Rust struct is expected to land alongside the M07 phase that wires the tool-call fabric to the provenance graph and the schema will be re-pinned to that serde shape at that time. Field names are camelCase to match the `GovernedCallChainContext` family this link binds to.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Verdict = Field(
        ...,
        description="Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.",
    )
    requestId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).",
    )
    receiptId: constr(min_length=1) | None = Field(
        None,
        description="Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
    )
    chainId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
    )
    renderedAt: conint(ge=0) = Field(
        ...,
        description="Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.",
    )
    reason: str | None = Field(
        None,
        description="Optional policy reason string. Required by the HTTP verdict union for `deny`, `cancel`, and `incomplete` verdicts. Omitted for `allow`.",
    )
    guard: str | None = Field(
        None,
        description="Optional policy guard identifier that produced a `deny` verdict. Mirrors the `guard` field on the HTTP verdict union. Omitted for non-deny verdicts.",
    )
    evidenceClass: EvidenceClass | None = Field(
        None,
        description="Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.",
    )
