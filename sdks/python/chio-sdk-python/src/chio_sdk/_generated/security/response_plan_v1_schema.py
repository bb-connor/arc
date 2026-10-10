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
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr
from . import response_effect_v1_schema

class SchemaVersion(Enum):
    integer_1 = 1

class SecurityResponsePlanV1DefinitionsExecutionBindingMode(Enum):
    dry_run = 'dry_run'
    live = 'live'

class SecurityResponsePlanV1DefinitionsExecutionBinding(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: SchemaVersion
    mode: SecurityResponsePlanV1DefinitionsExecutionBindingMode

class Identifier(RootModel[constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)]):
    root: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

class DigestItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class Digest(RootModel[list[DigestItem]]):
    root: list[DigestItem] = Field(..., max_length=32, min_length=32)

class Time(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class SecurityResponsePlanV1DefinitionsOperatorCapability(BaseModel):
    model_config = ConfigDict(extra='forbid')
    capability_id: Identifier
    capability_digest: Digest
    expires_at_unix_ms: Time
    executor_subject: Identifier

class SecurityResponsePlanV1DefinitionsApprovalRequirementVariant0(BaseModel):
    model_config = ConfigDict(extra='forbid')
    approval_type: Literal['automatic']

class SecurityResponsePlanV1DefinitionsApprovalRequirementVariant1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    approval_type: Literal['governed']
    policy_id: Identifier

class ApprovalRequirement(RootModel[SecurityResponsePlanV1DefinitionsApprovalRequirementVariant0 | SecurityResponsePlanV1DefinitionsApprovalRequirementVariant1]):
    root: SecurityResponsePlanV1DefinitionsApprovalRequirementVariant0 | SecurityResponsePlanV1DefinitionsApprovalRequirementVariant1

class ChioResponsePlanV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    action_id: Identifier
    trigger_finding_id: Identifier
    trigger_finding_hash: Digest
    trigger_finding_receipt_id: Identifier
    tenant_id: Identifier
    policy_version: Identifier
    policy_hash: Digest
    affected_ids: list[Identifier] = Field(..., max_length=4096, min_length=1)
    affected_set_hash: Digest
    effects: list[response_effect_v1_schema.ChioResponseEffectV1] = Field(..., max_length=64, min_length=1)
    ttl_ms: Time
    created_at_unix_ms: Time
    expires_at_unix_ms: Time
    operator_capability: SecurityResponsePlanV1DefinitionsOperatorCapability
    approval_requirement: ApprovalRequirement
    execution: SecurityResponsePlanV1DefinitionsExecutionBinding
    submitter: Identifier
    reason_hash: Digest
    plan_hash: Digest

# Public compatibility aliases reference the actual current model classes.
ApprovalRequirement1 = SecurityResponsePlanV1DefinitionsApprovalRequirementVariant0
ApprovalRequirement2 = SecurityResponsePlanV1DefinitionsApprovalRequirementVariant1
ExecutionBinding = SecurityResponsePlanV1DefinitionsExecutionBinding
Mode = SecurityResponsePlanV1DefinitionsExecutionBindingMode
OperatorCapability = SecurityResponsePlanV1DefinitionsOperatorCapability
SecurityResponsePlanV1ApprovalRequirement = ApprovalRequirement
SecurityResponsePlanV1ChioResponsePlanV1 = ChioResponsePlanV1
SecurityResponsePlanV1Digest = Digest
SecurityResponsePlanV1DigestItem = DigestItem
SecurityResponsePlanV1Identifier = Identifier
SecurityResponsePlanV1SchemaVersion = SchemaVersion
SecurityResponsePlanV1Time = Time
