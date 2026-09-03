# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 389bcf1b0204c491a4db719480c568ace486987ea9871d15adefdc3bb3a365cc
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class ChioBrokerAuditRunnerAuthorizationBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.broker-audit-runner-authorization.v1"] = Field(
        ..., alias="schema"
    )
    auditId: Identifier
    deploymentId: Identifier
    brokerInstanceId: Identifier
    tenantScope: Identifier
    runnerId: Identifier
    referenceSource: Identifier
    referenceCommitmentSha256: Digest
    capabilitySha256: Digest
    proofSha256: Digest
    canonicalRequestSha256: Digest
    providerAdapterId: Identifier
    providerAdapterVersion: conint(ge=1, le=4294967295)
    credentialProvider: Identifier
    revocationAuthorityDomain: Identifier
    issuedAtUnixSeconds: conint(ge=1)
    expiresAtUnixSeconds: conint(ge=1)
