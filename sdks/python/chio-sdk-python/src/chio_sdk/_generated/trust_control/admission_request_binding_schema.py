# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0a3a1765a96b67781f41c28a0d27ad221b6ab37620da7ca89acc92357927dee9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class OptionalDigest(RootModel[Digest | None]):
    root: Digest | None


class OptionalIdentifier(RootModel[Identifier | None]):
    root: Identifier | None


class ChioAdmissionOperationRequestBindingProjection1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionHash: Digest
    approvalTokenDigests: Annotated[list[Digest], Field(max_length=32)]
    budgetHoldReference: OptionalIdentifier
    executionNonceReference: OptionalIdentifier
    governedIntentHash: OptionalDigest
    policyHash: Digest
    supplementalAuthorizationDigest: OptionalDigest
    supplementalAuthorizationReference: OptionalIdentifier
    thresholdProposalHash: OptionalDigest
    verifiedApprovalSetHash: OptionalDigest


class ChioAdmissionOperationRequestBindingProjection2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionHash: Digest
    approvalTokenDigests: Annotated[list[Digest], Field(max_length=32)]
    budgetHoldReference: OptionalIdentifier
    executionNonceReference: OptionalIdentifier
    governedIntentHash: OptionalDigest
    policyHash: Digest
    supplementalAuthorizationDigest: Digest
    supplementalAuthorizationReference: Identifier
    thresholdProposalHash: OptionalDigest
    verifiedApprovalSetHash: OptionalDigest


class ChioAdmissionOperationRequestBindingProjection(
    RootModel[
        ChioAdmissionOperationRequestBindingProjection1
        | ChioAdmissionOperationRequestBindingProjection2
    ]
):
    root: Annotated[
        ChioAdmissionOperationRequestBindingProjection1
        | ChioAdmissionOperationRequestBindingProjection2,
        Field(title="Chio admission operation request-binding projection"),
    ]
