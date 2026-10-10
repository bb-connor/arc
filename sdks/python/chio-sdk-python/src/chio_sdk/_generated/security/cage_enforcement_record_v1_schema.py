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
from pydantic import BaseModel, ConfigDict, Field, RootModel
from . import cage_enforcement_failure_v1_schema, cage_fully_enforced_evidence_v1_schema, cage_process_exit_evidence_v1_schema

class SecurityCageEnforcementRecordV1State(Enum):
    unsupported = 'unsupported'
    rejected = 'rejected'
    bootstrap_failed = 'bootstrap_failed'
    fully_enforced = 'fully_enforced'
    exited = 'exited'

class SecurityCageEnforcementRecordV1Variant2State(Enum):
    unsupported = 'unsupported'
    rejected = 'rejected'
    bootstrap_failed = 'bootstrap_failed'
    fully_enforced = 'fully_enforced'
    exited = 'exited'
    unsupported_1 = 'unsupported'
    rejected_1 = 'rejected'
    bootstrap_failed_1 = 'bootstrap_failed'

class SecurityCageEnforcementRecordV1FullyEnforced(BaseModel):
    """
    Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.
    """
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.cage.enforcement-record.v1'] = Field(..., alias='schema')
    state: Literal['fully_enforced']
    fully_enforced: cage_fully_enforced_evidence_v1_schema.ChioCageFullyEnforcedEvidenceV1
    failure: cage_enforcement_failure_v1_schema.ChioCageEnforcementFailureV1 | None = None
    exit: cage_process_exit_evidence_v1_schema.ChioCageProcessExitEvidenceV1 | None = None

class SecurityCageEnforcementRecordV1Exited(BaseModel):
    """
    Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.
    """
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.cage.enforcement-record.v1'] = Field(..., alias='schema')
    state: Literal['exited']
    fully_enforced: cage_fully_enforced_evidence_v1_schema.ChioCageFullyEnforcedEvidenceV1
    failure: cage_enforcement_failure_v1_schema.ChioCageEnforcementFailureV1 | None = None
    exit: cage_process_exit_evidence_v1_schema.ChioCageProcessExitEvidenceV1

class SecurityCageEnforcementRecordV1Variant2(BaseModel):
    """
    Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.
    """
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.cage.enforcement-record.v1'] = Field(..., alias='schema')
    state: SecurityCageEnforcementRecordV1Variant2State
    fully_enforced: cage_fully_enforced_evidence_v1_schema.ChioCageFullyEnforcedEvidenceV1 | None = None
    failure: cage_enforcement_failure_v1_schema.ChioCageEnforcementFailureV1
    exit: cage_process_exit_evidence_v1_schema.ChioCageProcessExitEvidenceV1 | None = None

class ChioCageEnforcementRecordV1(RootModel[SecurityCageEnforcementRecordV1FullyEnforced | SecurityCageEnforcementRecordV1Exited | SecurityCageEnforcementRecordV1Variant2]):
    root: SecurityCageEnforcementRecordV1FullyEnforced | SecurityCageEnforcementRecordV1Exited | SecurityCageEnforcementRecordV1Variant2 = Field(..., description='Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.', title='Chio cage enforcement record v1')

# Public compatibility aliases reference the actual current model classes.
ChioCageEnforcementRecordV11 = SecurityCageEnforcementRecordV1FullyEnforced
ChioCageEnforcementRecordV12 = SecurityCageEnforcementRecordV1Exited
ChioCageEnforcementRecordV13 = SecurityCageEnforcementRecordV1Variant2
SecurityCageEnforcementRecordV1ChioCageEnforcementRecordV1 = ChioCageEnforcementRecordV1
State = SecurityCageEnforcementRecordV1State
State2 = SecurityCageEnforcementRecordV1Variant2State
State3 = SecurityCageEnforcementRecordV1Variant2State
