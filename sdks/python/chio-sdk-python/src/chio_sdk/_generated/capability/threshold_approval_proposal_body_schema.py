# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class GovernanceIdentifier(RootModel[str]):
    root: Annotated[str, Field(max_length=256, min_length=1)]


class PublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class ChioThresholdApprovalProposalBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorizationCapabilityHash: Digest
    eligibleSetDigest: Digest
    governedIntentHash: Digest
    policyHash: Digest
    proposalCreatedAt: Annotated[int, Field(ge=0)]
    proposalDeadline: Annotated[int, Field(ge=1)]
    proposalId: GovernanceIdentifier
    requestId: GovernanceIdentifier
    required: Annotated[int, Field(ge=1, le=32)]
    schema_: Annotated[
        Literal["chio.threshold-approval-proposal.v1"], Field(alias="schema")
    ]
    subject: PublicKey
