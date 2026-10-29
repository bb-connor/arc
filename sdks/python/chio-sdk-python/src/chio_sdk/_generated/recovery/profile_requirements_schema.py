# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7c51d7910f0345879134e0bf5bbb042abd7b8dbfdcd23700753b77f6814a0f36
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from . import observation_schema


class AttachmentProfile(Enum):
    ordinary = "ordinary"
    operation_owned_nonce = "operation_owned_nonce"


class RequiredFeature(Enum):
    native_capture = "native_capture"
    recovery_bound_grant = "recovery_bound_grant"
    exact_request_custody = "exact_request_custody"
    current_audience = "current_audience"
    operation_owned_nonce = "operation_owned_nonce"


class RecoveryProfileRequirementsV1(BaseModel):
    """
    Operator requirements. Canonical feature order follows the listed vocabulary and is checked by Rust. A matching inventory is not live enforcement qualification.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    required_features: Any | None = None
    protocol_version: Literal[1]
    deployment_digest: observation_schema.RecoveryDigest32
    attachment_profile: AttachmentProfile
    schema_: Literal["chio.recovery.profile-requirements.v1"] = Field(
        ..., alias="schema"
    )
