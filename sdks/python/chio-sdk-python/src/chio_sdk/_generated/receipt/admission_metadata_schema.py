# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class CompensationStatus(Enum):
    not_compensated = "not_compensated"
    compensated_before_dispatch = "compensated_before_dispatch"
    not_accepted_after_dispatch_commit = "not_accepted_after_dispatch_commit"


class ProjectedDispatchState(Enum):
    not_committed = "not_committed"
    capture_pending = "capture_pending"
    committed = "committed"
    finalizing = "finalizing"
    terminal = "terminal"
    not_applicable = "not_applicable"


class ProjectedState(Enum):
    prepared = "prepared"
    broker_attempt_registered = "broker_attempt_registered"
    approval_required = "approval_required"
    budget_authorized = "budget_authorized"
    approval_reserved = "approval_reserved"
    ready_to_dispatch = "ready_to_dispatch"
    capture_pending = "capture_pending"
    dispatch_committed = "dispatch_committed"
    finalizing = "finalizing"
    completed = "completed"
    compensated_before_dispatch = "compensated_before_dispatch"
    not_accepted_after_dispatch_commit = "not_accepted_after_dispatch_commit"
    outcome_unknown_after_dispatch = "outcome_unknown_after_dispatch"
    mutation_ready = "mutation_ready"
    mutation_submitted = "mutation_submitted"
    economic_mutation_applied = "economic_mutation_applied"
    economic_mutation_not_applied = "economic_mutation_not_applied"


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class PositiveIJsonInteger(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=9007199254740991)]


class ProviderAttempt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attempt_id: Identifier
    operation_id: Digest
    transport_id: Identifier
    transport_key_epoch: PositiveIJsonInteger


class StoreFence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lease_id: Identifier
    owner_epoch: PositiveIJsonInteger
    store_uuid: Identifier


class DispatchCommit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    committed_version: PositiveIJsonInteger
    coordinator_lease_epoch: PositiveIJsonInteger
    coordinator_lease_id: Identifier
    provider_attempt: ProviderAttempt | None = None
    store_fence: StoreFence


class ChioDurableAdmissionReceiptMetadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    compensation_status: CompensationStatus
    coordinator_lease_epoch: PositiveIJsonInteger
    coordinator_lease_id: Identifier
    operation_id: Digest
    projected_dispatch_state: ProjectedDispatchState
    projected_operation_version: PositiveIJsonInteger
    projected_state: ProjectedState
    request_binding_hash: Digest
    request_id: Identifier
    request_namespace_digest: Digest
    retained_dispatch_commit: DispatchCommit | None = None
    schema_: Annotated[Literal["chio.admission-receipt.v1"], Field(alias="schema")]
    store_fence: StoreFence
    tool_outcome_id: Digest | None = None
    tool_outcome_version: PositiveIJsonInteger | None = None
    trusted_time_unix_ms: PositiveIJsonInteger
