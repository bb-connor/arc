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
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class OrderedEffect(Enum):
    throttle_session = "throttle_session"
    restrict_egress = "restrict_egress"
    suspend_session = "suspend_session"
    suspend_capability_set = "suspend_capability_set"
    freeze_issuance = "freeze_issuance"


class ChioGovernedActiveResponseIntentBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    canonical_plan_body: dict[str, Any]
    executor_subject: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
    expires_at: Annotated[int, Field(ge=1)]
    operator_capability_expires_at: Annotated[int, Field(ge=1)]
    operator_capability_hash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    operator_capability_id: Annotated[str, Field(min_length=1)]
    ordered_effects: Annotated[list[OrderedEffect], Field(max_length=32, min_length=1)]
    plan_body_hash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    plan_id: Annotated[str, Field(min_length=1)]
    plan_schema: Literal["chio.governed-response-plan.v1"]
    rollback_binding: dict[str, Any]
    target_binding: dict[str, Any]
