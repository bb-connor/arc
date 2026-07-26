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

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class ChioBrokerAuditComparisonBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    accountingMutationCount: Literal[0]
    auditAuthorizationSha256: Digest
    auditIdSha256: Digest
    authorityContextSha256: Digest
    brokerOutboundProjectionCommitmentSha256: Digest
    canonicalRequestSha256: Digest
    capabilitySha256: Digest
    governedAuditIntentSha256: Digest
    issuedAtUnixSeconds: Annotated[int, Field(ge=1)]
    networkDispatchCount: Literal[0]
    projectionsEqual: bool
    proofSha256: Digest
    rawCredentialReturned: Literal[False]
    referenceOutboundProjectionCommitmentSha256: Digest
    referenceSourceSha256: Digest
    runnerAuthorizationSha256: Digest
    schema_: Annotated[
        Literal["chio.broker-audit-comparison.v1"], Field(alias="schema")
    ]
