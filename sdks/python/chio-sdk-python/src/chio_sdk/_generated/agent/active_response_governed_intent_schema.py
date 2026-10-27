# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 31d6c58928f59b213048f56bd61de1f7c959dead0e1721466dfb4f053e01ce6a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from chio_sdk._manifest_wire import SecurityWireModel as BaseModel

from pydantic import ConfigDict, Field, conint, constr, model_validator


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
    plan_schema: Literal["chio.response-plan.v1"]
    plan_id: constr(
        pattern=r"^[^\u0000-\u0020\u007F-\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000](?:[^\u0000-\u001F\u007F-\u009F]*[^\u0000-\u0020\u007F-\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000])?$",
        min_length=1,
        max_length=256,
    ) = Field(
        ...,
        description="At most 256 UTF-8 bytes, without control characters or surrounding whitespace.",
    )
    operator_capability_id: constr(
        pattern=r"^[^\u0000-\u0020\u007F-\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000](?:[^\u0000-\u001F\u007F-\u009F]*[^\u0000-\u0020\u007F-\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000])?$",
        min_length=1,
        max_length=256,
    ) = Field(
        ...,
        description="At most 256 UTF-8 bytes, without control characters or surrounding whitespace.",
    )
    operator_capability_hash: constr(pattern=r"^[0-9a-f]{64}$")
    operator_capability_expires_at: conint(strict=True, ge=1)
    executor_subject: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )
    canonical_plan_body: dict[str, Any] = Field(
        ...,
        description="Plan body hashed into plan_body_hash. Its RFC 8785 canonical form is at most 65536 bytes, nests at most 32 levels below the root and holds at most 4096 JSON values.",
    )
    plan_body_hash: constr(pattern=r"^[0-9a-f]{64}$")
    target_binding: dict[str, Any] = Field(
        ...,
        description="Its RFC 8785 canonical form is at most 16384 bytes, nests at most 32 levels below the root and holds at most 4096 JSON values.",
    )
    ordered_effects: list[OrderedEffect] = Field(..., max_length=5, min_length=1)
    expires_at: conint(strict=True, ge=1) = Field(
        ..., description="Must not exceed operator_capability_expires_at."
    )
    rollback_binding: dict[str, Any] = Field(
        ...,
        description="Its RFC 8785 canonical form is at most 16384 bytes, nests at most 32 levels below the root and holds at most 4096 JSON values.",
    )

    @model_validator(mode="after")
    def _validate_plan_shape(self) -> "ChioGovernedActiveResponseIntentBody":
        if len(set(self.ordered_effects)) != len(self.ordered_effects):
            raise ValueError("ordered_effects must be unique")
        if not (self.canonical_plan_body and self.target_binding and self.rollback_binding):
            raise ValueError("plan body and bindings must be nonempty objects")
        if "planHash" in self.canonical_plan_body or "plan_hash" in self.canonical_plan_body:
            raise ValueError("canonical_plan_body must not carry a plan hash")
        return self
