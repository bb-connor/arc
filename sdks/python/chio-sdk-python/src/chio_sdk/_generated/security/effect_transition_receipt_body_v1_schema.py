# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: e7734a10ce3d0e21e8497fad86bfb2a97e79c44ce827e678a869c592687f8837
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import response_state_transition_receipt_body_v1_schema
from .response_state_transition_receipt_body_v1_schema import Header as Header_1


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


class Outcome2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    resulting_version_hash: response_state_transition_receipt_body_v1_schema.Digest
    state: Literal["applied"]


class Outcome3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    error_code: response_state_transition_receipt_body_v1_schema.Identifier
    state: Literal["apply_failed"]


class Outcome5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    resulting_version_hash: response_state_transition_receipt_body_v1_schema.Digest
    state: Literal["restored"]


class Outcome6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    error_code: response_state_transition_receipt_body_v1_schema.Identifier
    state: Literal["rollback_failed"]


class Outcome(
    RootModel[Outcome1 | Outcome2 | Outcome3 | Outcome4 | Outcome5 | Outcome6]
):
    root: Outcome1 | Outcome2 | Outcome3 | Outcome4 | Outcome5 | Outcome6


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
    session_id: response_state_transition_receipt_body_v1_schema.Identifier
    target_type: Literal["session"]


class Target3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lineage_id: response_state_transition_receipt_body_v1_schema.Identifier
    target_type: Literal["lineage"]


class Target4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    affected_set_hash: response_state_transition_receipt_body_v1_schema.Digest
    target_type: Literal["capability_set"]


class Target(RootModel[Target1 | Target2 | Target3 | Target4]):
    root: Target1 | Target2 | Target3 | Target4


class Header(Header_1):
    prior_receipt_ids: Annotated[list | None, Field(max_length=1)] = None


class Effect(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    contribution_hash: response_state_transition_receipt_body_v1_schema.Digest
    effect_id: response_state_transition_receipt_body_v1_schema.Identifier
    kind: Kind
    observed_base_version_hash: response_state_transition_receipt_body_v1_schema.Digest
    ordinal: Annotated[int, Field(ge=0, le=65535)]
    target: Target


class ChioEffectTransitionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effect: Effect
    generation: Annotated[int, Field(ge=1, le=9007199254740991)]
    header: Header
    outcome: Outcome
    response: response_state_transition_receipt_body_v1_schema.Response
    scheduler_fencing_token: Annotated[int, Field(ge=1, le=9007199254740991)]
    scheduler_lease_owner_id: (
        response_state_transition_receipt_body_v1_schema.Identifier | None
    ) = None
