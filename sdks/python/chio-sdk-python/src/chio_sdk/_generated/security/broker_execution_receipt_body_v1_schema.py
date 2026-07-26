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

from . import broker_capability_body_v1_schema, broker_execution_evidence_v1_schema


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class PublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class Quota(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    keyId: Identifier
    maximumExecutions: Annotated[int, Field(ge=1, le=4294967295)]


class ChioBrokerExecutionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorizeEventId: Identifier
    brokerCapabilityId: Identifier
    brokerQuotaKeyId: Identifier
    callerHeadersSha256: Digest
    callerOptionsSha256: Digest
    captureEventId: Identifier
    credentialReferenceHash: Digest
    credentialVersion: Annotated[int, Field(ge=1)]
    evidence: broker_execution_evidence_v1_schema.ChioBrokerExecutionEvidenceV1
    issuedAtUnixSeconds: Annotated[int, Field(ge=1)]
    normalizedDestination: broker_capability_body_v1_schema.Destination
    operationId: Identifier
    outcome: Literal["completed"]
    parentCapabilityId: Identifier
    providerAdapterId: Identifier
    providerAdapterVersion: Annotated[int, Field(ge=1, le=4294967295)]
    quotas: Annotated[list[Quota], Field(max_length=8, min_length=1)]
    receiptId: Identifier
    requestBodyBytes: Annotated[int, Field(ge=0, le=524288)]
    requestBodySha256: Digest
    responseBodyBytes: Annotated[int, Field(ge=0, le=2097152)]
    schema_: Annotated[
        Literal["chio.broker-execution-receipt.v1"], Field(alias="schema")
    ]
    sourceReceiptIds: Annotated[list[Identifier], Field(max_length=64, min_length=0)]
    subject: PublicKey
