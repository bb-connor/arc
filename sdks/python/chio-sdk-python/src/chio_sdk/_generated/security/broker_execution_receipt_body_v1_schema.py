# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9695e2b405d3cd46de929a925e1a3b9b33ec4a67a0a5e93f625c433f820e1920
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import broker_capability_body_v1_schema, broker_execution_evidence_v1_schema


class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class PublicKey(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )


class Quota(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    keyId: Identifier
    maximumExecutions: conint(ge=1, le=4294967295)


class ChioBrokerExecutionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.broker-execution-receipt.v1"] = Field(..., alias="schema")
    receiptId: Identifier
    issuedAtUnixSeconds: conint(ge=1)
    evidence: broker_execution_evidence_v1_schema.ChioBrokerExecutionEvidenceV1
    operationId: Identifier
    authorizeEventId: Identifier
    captureEventId: Identifier
    parentCapabilityId: Identifier
    brokerCapabilityId: Identifier
    subject: PublicKey
    credentialReferenceHash: Digest
    credentialVersion: conint(ge=1)
    normalizedDestination: broker_capability_body_v1_schema.Destination
    requestBodySha256: Digest
    callerHeadersSha256: Digest
    callerOptionsSha256: Digest
    quotas: list[Quota] = Field(..., max_length=8, min_length=1)
    brokerQuotaKeyId: Identifier
    providerAdapterId: Identifier
    providerAdapterVersion: conint(ge=1, le=4294967295)
    requestBodyBytes: conint(ge=0, le=524288)
    responseBodyBytes: conint(ge=0, le=2097152)
    sourceReceiptIds: list[Identifier] = Field(..., max_length=64, min_length=0)
    outcome: Literal["completed"]
