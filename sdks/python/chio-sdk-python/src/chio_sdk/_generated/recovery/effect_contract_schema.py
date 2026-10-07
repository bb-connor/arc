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
from pydantic import field_validator
from pydantic import BaseModel, ConfigDict, Field, conint
from . import observation_schema, profile_requirements_schema

class RecoveryEffectContractLookupFinality(Enum):
    unavailable = 'unavailable'
    exact_operation_authoritative_final = 'exact_operation_authoritative_final'

class SemanticEffectContractV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.semantic.effect-contract.v1'] = Field(..., alias='schema')
    version: Literal[1]
    provider_id: observation_schema.OpaqueId
    account_id: observation_schema.OpaqueId
    resource_id: observation_schema.OpaqueId
    effect_cardinality: conint(ge=1, le=16)
    submission_identity: Literal['original_native_operation']
    transport_retry: Literal['no_automatic_retries']
    deduplication: Literal['not_assumed']
    lookup_finality: RecoveryEffectContractLookupFinality
    partial_settlement: Literal['preserve_spent_identity']
    recovery_profile: profile_requirements_schema.RecoveryProfileRequirementsV1

    @field_validator('version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
LookupFinality = RecoveryEffectContractLookupFinality
RecoveryEffectContractSemanticEffectContractV1 = SemanticEffectContractV1
