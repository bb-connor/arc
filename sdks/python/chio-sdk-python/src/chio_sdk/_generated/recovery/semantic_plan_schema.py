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
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class RecoverySemanticPlanDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoverySemanticPlanDefinitionsSemanticPlanInputExact(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['exact']
    resource: OpaqueId
    version: RecoveryDigest32
    material: RecoveryDigest32

class RecoverySemanticPlanDefinitionsSemanticPlanInputFutureOutput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['future_output']
    step: OpaqueId

class SemanticPlanInput(RootModel[RecoverySemanticPlanDefinitionsSemanticPlanInputExact | RecoverySemanticPlanDefinitionsSemanticPlanInputFutureOutput]):
    root: RecoverySemanticPlanDefinitionsSemanticPlanInputExact | RecoverySemanticPlanDefinitionsSemanticPlanInputFutureOutput

class RecoverySemanticPlanDefinitionsSemanticPlanStepOutput(Enum):
    return_value = 'return_value'
    withhold = 'withhold'

class RecoverySemanticPlanDefinitionsSemanticPlanStep(BaseModel):
    model_config = ConfigDict(extra='forbid')
    step: OpaqueId
    operation: OpaqueId
    destination: OpaqueId
    dependencies: list[OpaqueId] = Field(..., max_length=8, min_length=0)
    inputs: list[SemanticPlanInput] = Field(..., max_length=16, min_length=1)
    output: RecoverySemanticPlanDefinitionsSemanticPlanStepOutput

class SemanticPlanV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    domain_version: Literal[1]
    scope: RecoverySemanticPlanDefinitionsScope
    registry: RecoveryDigest32
    steps: list[RecoverySemanticPlanDefinitionsSemanticPlanStep] = Field(..., max_length=16, min_length=1)

    @field_validator('domain_version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
Output = RecoverySemanticPlanDefinitionsSemanticPlanStepOutput
RecoveryDigest32Item = RecoveryDigestOctet
RecoverySemanticPlanOpaqueId = OpaqueId
RecoverySemanticPlanRecoveryDigest32 = RecoveryDigest32
RecoverySemanticPlanRecoveryDigestOctet = RecoveryDigestOctet
RecoverySemanticPlanSemanticPlanInput = SemanticPlanInput
RecoverySemanticPlanSemanticPlanV1 = SemanticPlanV1
Scope = RecoverySemanticPlanDefinitionsScope
SemanticPlanInput1 = RecoverySemanticPlanDefinitionsSemanticPlanInputExact
SemanticPlanInput2 = RecoverySemanticPlanDefinitionsSemanticPlanInputFutureOutput
SemanticPlanStep = RecoverySemanticPlanDefinitionsSemanticPlanStep
