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

from pydantic import BaseModel, ConfigDict, Field

from . import partition_escrow_quota_commitment_schema


class Allocation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allocatedInvocations: partition_escrow_quota_commitment_schema.PartitionEscrowUint32
    authorityId: partition_escrow_quota_commitment_schema.PartitionEscrowIdentifier
    partitionId: partition_escrow_quota_commitment_schema.PartitionEscrowIdentifier


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allocationEpoch: (
        partition_escrow_quota_commitment_schema.PartitionEscrowPositiveSafeInteger
    )
    allocationPlanDigest: partition_escrow_quota_commitment_schema.PartitionEscrowDigest
    allocationRootId: partition_escrow_quota_commitment_schema.PartitionEscrowIdentifier
    allocations: Annotated[
        list[Allocation],
        Field(
            description="The complete allocation set. Runtime validation additionally requires bytewise ordering, unique partition and authority identifiers, and a sum no greater than quota.maxInvocations.",
            max_length=64,
            min_length=1,
        ),
    ]
    authorityDomain: partition_escrow_quota_commitment_schema.PartitionEscrowIdentifier
    expiresAt: Annotated[
        partition_escrow_quota_commitment_schema.PartitionEscrowPositiveSafeInteger,
        Field(
            description="Exclusive allocation expiry. Runtime validation also requires notBefore < expiresAt <= quotaCommitmentExpiresAt."
        ),
    ]
    notBefore: partition_escrow_quota_commitment_schema.PartitionEscrowSafeInteger
    quota: partition_escrow_quota_commitment_schema.PartitionEscrowQuota
    quotaCommitmentDigest: (
        partition_escrow_quota_commitment_schema.PartitionEscrowDigest
    )
    quotaCommitmentExpiresAt: (
        partition_escrow_quota_commitment_schema.PartitionEscrowPositiveSafeInteger
    )
    schema_: Annotated[
        Literal["chio.partition-escrow-allocation-set.v1"], Field(alias="schema")
    ]


class ChioSignedPartitionEscrowAllocationSet(BaseModel):
    """
    An allocator-signed, complete partition allocation plan derived from one source-signed quota commitment.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    algorithm: (
        partition_escrow_quota_commitment_schema.PartitionEscrowSignatureAlgorithm
    )
    allocatorKey: partition_escrow_quota_commitment_schema.PartitionEscrowPublicKey
    body: Body
    signature: partition_escrow_quota_commitment_schema.PartitionEscrowSignature
