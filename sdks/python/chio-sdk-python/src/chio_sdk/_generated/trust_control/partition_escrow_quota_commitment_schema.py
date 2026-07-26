# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class PartitionEscrowDigest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class PartitionEscrowEd25519PublicKey(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class PartitionEscrowEd25519Signature(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{128}$")]


class PartitionEscrowHybridPublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65$"
        ),
    ]


class PartitionEscrowHybridSignature(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65$"
        ),
    ]


class PartitionEscrowIdentifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            description="A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.",
            max_length=512,
            min_length=1,
            pattern="^[^\\u0000]+$",
        ),
    ]


class PartitionEscrowP256PublicKey(RootModel[str]):
    root: Annotated[str, Field(pattern="^p256:[0-9a-f]{130}$")]


class PartitionEscrowP256Signature(RootModel[str]):
    root: Annotated[str, Field(pattern="^p256:[0-9a-f]+$")]


class PartitionEscrowP384PublicKey(RootModel[str]):
    root: Annotated[str, Field(pattern="^p384:[0-9a-f]{194}$")]


class PartitionEscrowP384Signature(RootModel[str]):
    root: Annotated[str, Field(pattern="^p384:[0-9a-f]+$")]


class PartitionEscrowPositiveSafeInteger(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=9007199254740991)]


class PartitionEscrowPositiveUint32(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=4294967295)]


class PartitionEscrowPublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class Profile(Enum):
    chio_grant_invocation_v1 = "chio.grant-invocation.v1"
    chio_aggregate_capability_invocation_v1 = "chio.aggregate-capability-invocation.v1"
    chio_aggregate_family_invocation_v1 = "chio.aggregate-family-invocation.v1"
    chio_broker_capability_execution_v1 = "chio.broker-capability-execution.v1"


class PartitionEscrowSafeInteger(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=9007199254740991)]


class PartitionEscrowSignature(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class PartitionEscrowSignatureAlgorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class PartitionEscrowUint32(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=4294967295)]


class PartitionEscrowQuota(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grantIndex: PartitionEscrowUint32 | None = None
    maxInvocations: PartitionEscrowUint32
    ownerId: PartitionEscrowIdentifier
    profile: Profile


class QuotaCommitmentBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allocationEpoch: PartitionEscrowPositiveSafeInteger
    allocationPlanDigest: PartitionEscrowDigest
    allocationRootId: PartitionEscrowIdentifier
    authorityDomain: PartitionEscrowIdentifier
    quota: PartitionEscrowQuota
    quotaKeyDigest: PartitionEscrowDigest
    schema_: Annotated[
        Literal["chio.partition-escrow-quota-commitment.v1"], Field(alias="schema")
    ]
    sourceExpiresAt: Annotated[
        PartitionEscrowPositiveSafeInteger,
        Field(
            description="Exclusive source authority expiry. Runtime validation also requires this value to be greater than sourceNotBefore."
        ),
    ]
    sourceNotBefore: PartitionEscrowSafeInteger
    sourceTrustBindingDigest: PartitionEscrowDigest
    underlyingSourceArtifactDigest: PartitionEscrowDigest


class ChioSignedPartitionEscrowQuotaCommitment(BaseModel):
    """
    A source-key-signed commitment binding one global invocation quota to an exact source artifact and complete partition allocation plan.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    algorithm: PartitionEscrowSignatureAlgorithm
    body: QuotaCommitmentBody
    signature: PartitionEscrowSignature
    signerKey: PartitionEscrowPublicKey
