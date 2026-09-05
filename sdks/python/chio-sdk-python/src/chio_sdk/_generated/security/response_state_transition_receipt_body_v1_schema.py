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

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


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


class Identifier(
    RootModel[
        constr(
            pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
            min_length=1,
            max_length=256,
        )
    ]
):
    root: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
        max_length=256,
    )


class DigestItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class Digest(RootModel[list[DigestItem]]):
    root: list[DigestItem] = Field(..., max_length=32, min_length=32)


class Time(RootModel[conint(ge=1, le=9007199254740991)]):
    root: conint(ge=1, le=9007199254740991)


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


class Header(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal[1]
    occurred_at_unix_ms: Time
    tenant_id: Identifier
    transition_id: Identifier
    prior_receipt_ids: list[Identifier] = Field(..., max_length=64, min_length=1)


class Policy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    policy_version: Identifier
    policy_hash: Digest


class Response(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    policy: Policy
    plan_hash: Digest
    action_id: Identifier
    trigger_finding_id: Identifier
    trigger_finding_hash: Digest
    trigger_finding_receipt_id: Identifier
    affected_set_hash: Digest
    plan_expires_at_unix_ms: Time


class Header4(Header):
    prior_receipt_ids: list | None = Field(None, max_length=1)


class ChioResponseStateTransitionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    header: Header4
    response: Response
    generation: conint(ge=1, le=9007199254740991)
    from_state: State
    to_state: State
    cause: Cause
    applying_lease_expires_at_unix_ms: Time | None = None
    scheduler_lease_owner_id: Identifier | None = None
    scheduler_fencing_token: conint(ge=1, le=9007199254740991) | None = None
    error_code: Identifier | None = None
