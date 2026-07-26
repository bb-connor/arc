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

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator

from . import budget_invocation_admission_evidence_schema


class GuaranteeLevel(Enum):
    single_node_atomic = "single_node_atomic"
    partition_escrowed = "partition_escrowed"
    ha_linearizable = "ha_linearizable"


class MonetaryState(Enum):
    none = "none"
    exposed = "exposed"
    released = "released"
    reconciled = "reconciled"
    captured = "captured"
    reversed = "reversed"


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class Authority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityId: Identifier
    leaseEpoch: Annotated[int, Field(ge=0)]
    leaseId: Identifier


class InvocationQuotaTransition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capturedInvocationsAfter: Annotated[int, Field(ge=1, le=4294967295)]
    capturedInvocationsBefore: Annotated[int, Field(ge=0, le=4294967295)]
    key: budget_invocation_admission_evidence_schema.QuotaKey
    maxInvocations: Annotated[int, Field(ge=0, le=4294967295)]
    reservedInvocationsAfter: Annotated[int, Field(ge=0, le=4294967295)]
    reservedInvocationsBefore: Annotated[int, Field(ge=1, le=4294967295)]


class ChioAuthoritativeAdmissionCaptureReceiptProjection(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregateRootBindingDigest: Digest | None = None
    aggregateRootCapabilityId: Identifier | None = None
    authority: Authority
    authorityCommitIndex: Annotated[int, Field(ge=0)]
    authorizationArtifactDigests: Annotated[
        list[Digest], Field(max_length=8, min_length=1)
    ]
    budgetCommitIndex: Annotated[int, Field(ge=1)]
    checkedRevocationSetDigest: Digest
    eventId: Identifier
    guaranteeLevel: GuaranteeLevel
    holdId: Identifier
    invocationQuotas: Annotated[
        list[InvocationQuotaTransition], Field(max_length=8, min_length=1)
    ]
    invocationState: Literal["captured"]
    leaderEpoch: Annotated[int | None, Field(ge=1)] = None
    monetaryState: MonetaryState
    operationId: Identifier
    partitionEscrowEvidence: (
        budget_invocation_admission_evidence_schema.PartitionEscrowEvidence | None
    ) = None
    revocationCommitIndex: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def _validate_guarantee_evidence(
        self,
    ) -> "ChioAuthoritativeAdmissionCaptureReceiptProjection":
        leader_epoch_present = "leaderEpoch" in self.model_fields_set
        partition_escrow_evidence_present = (
            "partitionEscrowEvidence" in self.model_fields_set
        )
        if self.guaranteeLevel is GuaranteeLevel.single_node_atomic:
            if leader_epoch_present or partition_escrow_evidence_present:
                raise ValueError(
                    "single_node_atomic forbids leaderEpoch and "
                    "partitionEscrowEvidence"
                )
        elif self.guaranteeLevel is GuaranteeLevel.partition_escrowed:
            if leader_epoch_present:
                raise ValueError("partition_escrowed forbids leaderEpoch")
            if (
                not partition_escrow_evidence_present
                or self.partitionEscrowEvidence is None
            ):
                raise ValueError(
                    "partition_escrowed requires partitionEscrowEvidence"
                )
        elif self.guaranteeLevel is GuaranteeLevel.ha_linearizable:
            if partition_escrow_evidence_present:
                raise ValueError(
                    "ha_linearizable forbids partitionEscrowEvidence"
                )
            if not leader_epoch_present or self.leaderEpoch is None:
                raise ValueError("ha_linearizable requires leaderEpoch")
        else:
            raise ValueError("unsupported admission capture guarantee level")
        return self
