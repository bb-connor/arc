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
from typing import Literal
from pydantic import field_validator
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr
from . import policy_trajectory_ref_schema

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class RecoveryPolicyMaintenanceProposalDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class PolicyMaintenanceProposalV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    domain_version: Literal[1]
    scope: RecoveryPolicyMaintenanceProposalDefinitionsScope
    proposal_id: OpaqueId
    report_id: OpaqueId
    base_deployment: RecoveryDigest32
    base_policy: RecoveryDigest32
    target_policy: RecoveryDigest32
    rationale: constr(min_length=1, max_length=4096)
    affected_contracts: list[RecoveryDigest32] = Field(..., max_length=16, min_length=1)
    benign_trajectories: list[policy_trajectory_ref_schema.PolicyTrajectoryRefV1] = Field(..., max_length=16, min_length=1)
    adversarial_trajectories: list[policy_trajectory_ref_schema.PolicyTrajectoryRefV1] = Field(..., max_length=16, min_length=1)
    expected_effects: constr(min_length=1, max_length=4096)
    rollback_policy: RecoveryDigest32
    rollback_plan: constr(min_length=1, max_length=4096)

    @field_validator('domain_version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryPolicyMaintenanceProposalOpaqueId = OpaqueId
RecoveryPolicyMaintenanceProposalPolicyMaintenanceProposalV1 = PolicyMaintenanceProposalV1
RecoveryPolicyMaintenanceProposalRecoveryDigest32 = RecoveryDigest32
RecoveryPolicyMaintenanceProposalRecoveryDigestOctet = RecoveryDigestOctet
RecoveryPolicyMaintenanceProposalSafeInteger = SafeInteger
Scope = RecoveryPolicyMaintenanceProposalDefinitionsScope
