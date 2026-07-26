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

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Cause(Enum):
    approval_requested = "approval_requested"
    approval_satisfied = "approval_satisfied"
    apply_started = "apply_started"
    apply_completed = "apply_completed"
    applying_lease_renewed = "applying_lease_renewed"
    applying_lease_expired = "applying_lease_expired"
    plan_expired = "plan_expired"
    operator_cancelled = "operator_cancelled"
    rollback_completed = "rollback_completed"
    rollback_failed = "rollback_failed"
    rollback_requested = "rollback_requested"
    rollback_retry = "rollback_retry"
    validation_failed = "validation_failed"


class SchedulerFencingToken(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=9007199254740991)]


class DigestItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class Digest(RootModel[list[DigestItem]]):
    root: Annotated[list[DigestItem], Field(max_length=32, min_length=32)]


class Identifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            max_length=256,
            min_length=1,
            pattern="^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        ),
    ]


class Policy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    policy_hash: Digest
    policy_version: Identifier


class State(Enum):
    planned = "planned"
    awaiting_approval = "awaiting_approval"
    applying = "applying"
    active = "active"
    apply_partial = "apply_partial"
    expiring = "expiring"
    rolling_back = "rolling_back"
    rollback_partial = "rollback_partial"
    cancelled = "cancelled"
    expired = "expired"
    failed = "failed"
    lifted = "lifted"


class Time(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=9007199254740991)]


class Header(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    occurred_at_unix_ms: Time
    prior_receipt_ids: Annotated[list[Identifier], Field(max_length=64, min_length=1)]
    schema_version: Literal[1]
    tenant_id: Identifier
    transition_id: Identifier


class Response(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_id: Identifier
    affected_set_hash: Digest
    plan_expires_at_unix_ms: Time
    plan_hash: Digest
    policy: Policy
    trigger_finding_hash: Digest
    trigger_finding_id: Identifier
    trigger_finding_receipt_id: Identifier


class Header5(Header):
    prior_receipt_ids: Annotated[list | None, Field(max_length=1)] = None


class ChioResponseStateTransitionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    applying_lease_expires_at_unix_ms: Time | None = None
    cause: Cause
    error_code: Identifier | None = None
    from_state: State
    generation: Annotated[int, Field(ge=1, le=9007199254740991)]
    header: Header5
    response: Response
    scheduler_fencing_token: SchedulerFencingToken | None = None
    scheduler_lease_owner_id: Identifier | None = None
    to_state: State
