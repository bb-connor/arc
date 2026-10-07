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
from typing import Any, Literal
from pydantic import field_validator
from pydantic import BaseModel, ConfigDict, Field
from . import observation_schema

class RecoveryProfileRequirementsAttachmentProfile(Enum):
    ordinary = 'ordinary'
    operation_owned_nonce = 'operation_owned_nonce'

class RecoveryProfileRequirementsRequiredFeaturesItems(Enum):
    native_capture = 'native_capture'
    recovery_bound_grant = 'recovery_bound_grant'
    exact_request_custody = 'exact_request_custody'
    current_audience = 'current_audience'
    operation_owned_nonce = 'operation_owned_nonce'

class RecoveryProfileRequirementsV1(BaseModel):
    """
    Operator requirements. Canonical feature order follows the listed vocabulary and is checked by Rust. A matching inventory is not live enforcement qualification.
    """
    model_config = ConfigDict(extra='forbid')
    required_features: Any | None = None
    protocol_version: Literal[1]
    deployment_digest: observation_schema.RecoveryDigest32
    attachment_profile: RecoveryProfileRequirementsAttachmentProfile
    schema_: Literal['chio.recovery.profile-requirements.v1'] = Field(..., alias='schema')

    @field_validator('protocol_version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
AttachmentProfile = RecoveryProfileRequirementsAttachmentProfile
RequiredFeature = RecoveryProfileRequirementsRequiredFeaturesItems
