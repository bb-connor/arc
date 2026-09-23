# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: a2de5a34e01a3345c9d1cfd8af54ab7b51bd57eed8cf608d3b84ede910af0a3e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class ChioBrokerAuditComparisonBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.broker-audit-comparison.v1"] = Field(..., alias="schema")
    issuedAtUnixSeconds: conint(ge=1)
    capabilitySha256: Digest
    proofSha256: Digest
    canonicalRequestSha256: Digest
    authorityContextSha256: Digest
    auditIdSha256: Digest
    governedAuditIntentSha256: Digest
    auditAuthorizationSha256: Digest
    runnerAuthorizationSha256: Digest
    referenceSourceSha256: Digest
    brokerOutboundProjectionCommitmentSha256: Digest
    referenceOutboundProjectionCommitmentSha256: Digest
    projectionsEqual: bool
    networkDispatchCount: Literal[0]
    accountingMutationCount: Literal[0]
    rawCredentialReturned: Literal[False]
