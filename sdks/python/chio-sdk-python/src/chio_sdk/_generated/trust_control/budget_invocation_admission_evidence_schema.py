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
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class PartitionEscrowEvidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    canonicalJson: Annotated[str, Field(max_length=1048576, min_length=2)]
    digest: Digest


class PublicKey(RootModel[str]):
    root: Annotated[
        str, Field(pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$")
    ]


class Profile(Enum):
    chio_grant_invocation_v1 = "chio.grant-invocation.v1"
    chio_aggregate_capability_invocation_v1 = "chio.aggregate-capability-invocation.v1"
    chio_aggregate_family_invocation_v1 = "chio.aggregate-family-invocation.v1"
    chio_broker_capability_execution_v1 = "chio.broker-capability-execution.v1"


class QuotaKey(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grantIndex: Annotated[int | None, Field(ge=0, le=4294967295)] = None
    ownerId: Identifier
    profile: Profile


class RevocationSet(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    digest: Digest
    ids: Annotated[list[Identifier], Field(max_length=128, min_length=1)]


class SafeInteger(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=9007199254740991)]


class SupplementalBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactDigest: Digest
    brokerCapabilityId: Identifier
    claimBindingDigest: Digest
    expiresAt: SafeInteger
    issuer: PublicKey
    negotiatedFeaturesDigest: Digest
    notBefore: SafeInteger
    requestBindingHash: Digest
    requestConstraintDigest: Digest
    verifiedAt: SafeInteger
    verifierId: Identifier


class InvocationQuota(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    key: QuotaKey
    maxInvocations: Annotated[int, Field(ge=0, le=4294967295)]


class ChioBudgetInvocationAdmissionEvidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregateBindingDigest: Digest | None = None
    aggregateRootCapabilityId: Identifier | None = None
    invocationQuotas: Annotated[
        list[InvocationQuota], Field(max_length=8, min_length=1)
    ]
    partitionEscrowEvidence: PartitionEscrowEvidence | None = None
    revocationSet: RevocationSet
    supplementalBinding: SupplementalBinding | None = None
