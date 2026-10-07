# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 35f8e30cf30553986a159b074ee485804a85db29547a8102522cd7bfa3080d2e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations
from enum import Enum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

class ReceiptAdmissionMetadataProjectedState(Enum):
    prepared = 'prepared'
    broker_attempt_registered = 'broker_attempt_registered'
    approval_required = 'approval_required'
    budget_authorized = 'budget_authorized'
    approval_reserved = 'approval_reserved'
    ready_to_dispatch = 'ready_to_dispatch'
    capture_pending = 'capture_pending'
    dispatch_committed = 'dispatch_committed'
    finalizing = 'finalizing'
    completed = 'completed'
    compensated_before_dispatch = 'compensated_before_dispatch'
    not_accepted_after_dispatch_commit = 'not_accepted_after_dispatch_commit'
    outcome_unknown_after_dispatch = 'outcome_unknown_after_dispatch'
    denied_after_delivery = 'denied_after_delivery'
    mutation_ready = 'mutation_ready'
    mutation_submitted = 'mutation_submitted'
    economic_mutation_applied = 'economic_mutation_applied'
    economic_mutation_not_applied = 'economic_mutation_not_applied'

class ReceiptAdmissionMetadataProjectedDispatchState(Enum):
    not_committed = 'not_committed'
    capture_pending = 'capture_pending'
    committed = 'committed'
    finalizing = 'finalizing'
    terminal = 'terminal'
    not_applicable = 'not_applicable'

class ReceiptAdmissionMetadataCompensationStatus(Enum):
    not_compensated = 'not_compensated'
    compensated_before_dispatch = 'compensated_before_dispatch'
    not_accepted_after_dispatch_commit = 'not_accepted_after_dispatch_commit'

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)

class PositiveIJsonInteger(RootModel[conint(ge=1, le=9007199254740991)]):
    root: conint(ge=1, le=9007199254740991)

class ReceiptAdmissionMetadataDefinitionsStoreFence(BaseModel):
    model_config = ConfigDict(extra='forbid')
    store_uuid: Identifier
    lease_id: Identifier
    owner_epoch: PositiveIJsonInteger

class ReceiptAdmissionMetadataDefinitionsProviderAttempt(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operation_id: Digest
    attempt_id: Identifier
    transport_id: Identifier
    transport_key_epoch: PositiveIJsonInteger

class ReceiptAdmissionMetadataDefinitionsDispatchCommit(BaseModel):
    model_config = ConfigDict(extra='forbid')
    committed_version: PositiveIJsonInteger
    coordinator_lease_id: Identifier
    coordinator_lease_epoch: PositiveIJsonInteger
    store_fence: ReceiptAdmissionMetadataDefinitionsStoreFence
    provider_attempt: ReceiptAdmissionMetadataDefinitionsProviderAttempt | None = None

class ChioDurableAdmissionReceiptMetadata(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.admission-receipt.v1'] = Field(..., alias='schema')
    operation_id: Digest
    request_id: Identifier
    request_namespace_digest: Digest
    request_binding_hash: Digest
    projected_operation_version: PositiveIJsonInteger
    projected_state: ReceiptAdmissionMetadataProjectedState
    projected_dispatch_state: ReceiptAdmissionMetadataProjectedDispatchState
    trusted_time_unix_ms: PositiveIJsonInteger
    coordinator_lease_id: Identifier
    coordinator_lease_epoch: PositiveIJsonInteger
    store_fence: ReceiptAdmissionMetadataDefinitionsStoreFence
    retained_dispatch_commit: ReceiptAdmissionMetadataDefinitionsDispatchCommit | None = None
    compensation_status: ReceiptAdmissionMetadataCompensationStatus
    tool_outcome_id: Digest | None = None
    tool_outcome_version: PositiveIJsonInteger | None = None

# Public compatibility aliases reference the actual current model classes.
CompensationStatus = ReceiptAdmissionMetadataCompensationStatus
DispatchCommit = ReceiptAdmissionMetadataDefinitionsDispatchCommit
ProjectedDispatchState = ReceiptAdmissionMetadataProjectedDispatchState
ProjectedState = ReceiptAdmissionMetadataProjectedState
ProviderAttempt = ReceiptAdmissionMetadataDefinitionsProviderAttempt
ReceiptAdmissionMetadataChioDurableAdmissionReceiptMetadata = ChioDurableAdmissionReceiptMetadata
ReceiptAdmissionMetadataDigest = Digest
ReceiptAdmissionMetadataIdentifier = Identifier
ReceiptAdmissionMetadataPositiveIJsonInteger = PositiveIJsonInteger
StoreFence = ReceiptAdmissionMetadataDefinitionsStoreFence
