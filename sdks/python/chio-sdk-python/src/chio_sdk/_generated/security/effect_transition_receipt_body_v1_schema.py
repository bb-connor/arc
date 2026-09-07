# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: c56ebd67862c888dd340e0ba3a14bf38d69abc45d8d02e706ed935cd512054ec
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint

from . import response_state_transition_receipt_body_v1_schema
from .response_state_transition_receipt_body_v1_schema import Header as Header_1


class JsonSafePositiveInteger(RootModel[conint(ge=1, le=9007199254740991)]):
    root: conint(ge=1, le=9007199254740991)


class Kind(Enum):
    escalate_alert = "escalate_alert"
    throttle_session = "throttle_session"
    restrict_egress = "restrict_egress"
    suspend_session = "suspend_session"
    suspend_capability_set = "suspend_capability_set"
    freeze_issuance = "freeze_issuance"


class Outcome1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["requested"]


class Outcome4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["rollback_requested"]


class Header(Header_1):
    prior_receipt_ids: list | None = Field(None, max_length=1)


class Target1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    target_type: Literal["tenant"]
    tenant_id: response_state_transition_receipt_body_v1_schema.Identifier


class Target2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    target_type: Literal["session"]
    session_id: response_state_transition_receipt_body_v1_schema.Identifier


class Target3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    target_type: Literal["lineage"]
    lineage_id: response_state_transition_receipt_body_v1_schema.Identifier


class Target4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    target_type: Literal["capability_set"]
    affected_set_hash: response_state_transition_receipt_body_v1_schema.Digest


class Target(RootModel[Target1 | Target2 | Target3 | Target4]):
    root: Target1 | Target2 | Target3 | Target4


class Effect(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effect_id: response_state_transition_receipt_body_v1_schema.Identifier
    ordinal: conint(ge=0, le=65535)
    kind: Kind
    target: Target
    contribution_hash: response_state_transition_receipt_body_v1_schema.Digest
    observed_base_version_hash: response_state_transition_receipt_body_v1_schema.Digest


class Outcome2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["applied"]
    resulting_version_hash: response_state_transition_receipt_body_v1_schema.Digest


class Outcome3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["apply_failed"]
    error_code: response_state_transition_receipt_body_v1_schema.Identifier


class Outcome5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["restored"]
    resulting_version_hash: response_state_transition_receipt_body_v1_schema.Digest


class Outcome6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["rollback_failed"]
    error_code: response_state_transition_receipt_body_v1_schema.Identifier


class Outcome(
    RootModel[Outcome1 | Outcome2 | Outcome3 | Outcome4 | Outcome5 | Outcome6]
):
    root: Outcome1 | Outcome2 | Outcome3 | Outcome4 | Outcome5 | Outcome6


class ChioEffectTransitionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    header: Header
    response: response_state_transition_receipt_body_v1_schema.Response
    effect: Effect
    generation: JsonSafePositiveInteger
    scheduler_lease_owner_id: (
        response_state_transition_receipt_body_v1_schema.Identifier | None
    ) = None
    scheduler_fencing_token: JsonSafePositiveInteger
    outcome: Outcome
