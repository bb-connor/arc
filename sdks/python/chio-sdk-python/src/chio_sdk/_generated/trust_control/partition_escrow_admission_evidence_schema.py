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

from . import (
    partition_escrow_allocation_set_schema,
    partition_escrow_quota_commitment_schema,
)


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            description="A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.",
            max_length=512,
            min_length=1,
            pattern="^[^\\u0000]+$",
        ),
    ]


class PositiveSafeInteger(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=9007199254740991)]


class PositiveUint32(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=4294967295)]


class PublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class Resolver(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    configurationDigest: Digest
    implementationId: Identifier
    implementationVersion: PositiveUint32
    resolverId: Identifier


class SafeInteger(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=9007199254740991)]


class Uint32(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=4294967295)]


class AggregateCapabilityTrust(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: Identifier
    kind: Literal["aggregateCapability"]
    revocation_set_digest: Digest


class AggregateFamilyTrust(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    family_owner: Digest
    kind: Literal["aggregateFamily"]
    revocation_set_digest: Digest
    root_binding_digest: Digest
    root_capability_id: Identifier


class BrokerCapabilityTrust(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    broker_capability_id: Identifier
    claim_binding_digest: Digest
    kind: Literal["brokerCapability"]
    negotiated_features_digest: Digest
    quota_owner_id: Digest
    request_binding_hash: Digest
    request_constraint_digest: Digest
    revocation_set_digest: Digest
    verifier_id: Identifier


class DurableStore(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    counterNamespaceDigest: Digest
    fencingToken: PositiveSafeInteger
    storeIdentityDigest: Digest


class GrantCapabilityTrust(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: Identifier
    grant_index: Uint32
    kind: Literal["grantCapability"]
    revocation_set_digest: Digest


class SourceTrust(
    RootModel[
        GrantCapabilityTrust
        | AggregateCapabilityTrust
        | AggregateFamilyTrust
        | BrokerCapabilityTrust
    ]
):
    root: Annotated[
        GrantCapabilityTrust
        | AggregateCapabilityTrust
        | AggregateFamilyTrust
        | BrokerCapabilityTrust,
        Field(
            description="The kind discriminator is camelCase. Variant payload fields remain snake_case because that is the exact serde representation."
        ),
    ]


class QuotaEvidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allocationEpoch: PositiveSafeInteger
    allocationPlanDigest: Digest
    allocationRootId: Identifier
    allocationSet: (
        partition_escrow_allocation_set_schema.ChioSignedPartitionEscrowAllocationSet
    )
    allocationSetDigest: Digest
    globalQuota: partition_escrow_quota_commitment_schema.PartitionEscrowQuota
    localAllocatedInvocations: Uint32
    quotaCertificateBindingDigest: Digest
    quotaCommitment: (
        partition_escrow_quota_commitment_schema.ChioSignedPartitionEscrowQuotaCommitment
    )
    quotaCommitmentDigest: Digest
    quotaDescriptorDigest: Digest
    quotaKeyDigest: Digest
    sourceExpiresAt: Annotated[
        PositiveSafeInteger,
        Field(
            description="Exclusive source authority expiry. Runtime validation also requires this value to be greater than sourceNotBefore."
        ),
    ]
    sourceNotBefore: SafeInteger
    sourceSigner: PublicKey
    sourceTrust: SourceTrust
    sourceTrustBindingDigest: Digest
    totalAllocatedInvocations: Uint32
    underlyingSourceArtifactDigest: Digest


class ChioPartitionEscrowAdmissionEvidence(BaseModel):
    """
    Canonical historical proof that a durable partition authority verified and admitted one or more source-backed invocation quotas.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    authorityDomain: Identifier
    authorityId: Identifier
    durableStore: DurableStore
    partitionId: Identifier
    quotas: Annotated[
        list[QuotaEvidence],
        Field(
            description="Quota keys and certificate bindings must be unique under runtime validation.",
            max_length=8,
            min_length=1,
        ),
    ]
    resolver: Resolver
    schema_: Annotated[
        Literal["chio.partition-escrow-admission-evidence.v1"], Field(alias="schema")
    ]
    verifiedAt: SafeInteger
