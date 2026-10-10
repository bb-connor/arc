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
from . import cage_enforcement_prepared_v1_schema, cage_enforcement_record_v1_schema

class SecurityCageReceiptBodyV1Stage(Enum):
    rejection = 'rejection'
    bootstrap = 'bootstrap'
    enforcement = 'enforcement'
    terminal_exit = 'terminal_exit'

class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class SecurityCageReceiptBodyV1DefinitionsBindings(BaseModel):
    model_config = ConfigDict(extra='forbid')
    manifest_digest: Digest
    profile_digest: Digest
    plan_digest: Digest
    fd_table_digest: Digest
    helper_binding_digest: Digest
    target_binding_digest: Digest
    target_identity: cage_enforcement_prepared_v1_schema.RegularFileIdentity

class SecurityCageReceiptBodyV1Rejection(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.cage.receipt-body.v1'] = Field(..., alias='schema')
    attempt_id: Identifier
    stage: Literal['rejection']
    bindings: SecurityCageReceiptBodyV1DefinitionsBindings | None = None
    enforcement_record: cage_enforcement_record_v1_schema.ChioCageEnforcementRecordV1
    started_at_unix_ms: conint(ge=1)
    recorded_at_unix_ms: conint(ge=1000)

class SecurityCageReceiptBodyV1Bootstrap(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.cage.receipt-body.v1'] = Field(..., alias='schema')
    attempt_id: Identifier
    stage: Literal['bootstrap']
    bindings: SecurityCageReceiptBodyV1DefinitionsBindings
    enforcement_record: cage_enforcement_record_v1_schema.ChioCageEnforcementRecordV1
    started_at_unix_ms: conint(ge=1)
    recorded_at_unix_ms: conint(ge=1000)

class SecurityCageReceiptBodyV1Enforcement(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.cage.receipt-body.v1'] = Field(..., alias='schema')
    attempt_id: Identifier
    stage: Literal['enforcement']
    bindings: SecurityCageReceiptBodyV1DefinitionsBindings
    enforcement_record: cage_enforcement_record_v1_schema.ChioCageEnforcementRecordV1
    started_at_unix_ms: conint(ge=1)
    recorded_at_unix_ms: conint(ge=1000)

class SecurityCageReceiptBodyV1TerminalExit(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.cage.receipt-body.v1'] = Field(..., alias='schema')
    attempt_id: Identifier
    stage: Literal['terminal_exit']
    bindings: SecurityCageReceiptBodyV1DefinitionsBindings
    enforcement_record: cage_enforcement_record_v1_schema.ChioCageEnforcementRecordV1
    started_at_unix_ms: conint(ge=1)
    recorded_at_unix_ms: conint(ge=1000)

class ChioCageReceiptBodyV1(RootModel[SecurityCageReceiptBodyV1Rejection | SecurityCageReceiptBodyV1Bootstrap | SecurityCageReceiptBodyV1Enforcement | SecurityCageReceiptBodyV1TerminalExit]):
    root: SecurityCageReceiptBodyV1Rejection | SecurityCageReceiptBodyV1Bootstrap | SecurityCageReceiptBodyV1Enforcement | SecurityCageReceiptBodyV1TerminalExit = Field(..., title='Chio cage receipt body v1')

# Public compatibility aliases reference the actual current model classes.
Bindings = SecurityCageReceiptBodyV1DefinitionsBindings
ChioCageReceiptBodyV11 = SecurityCageReceiptBodyV1Rejection
ChioCageReceiptBodyV12 = SecurityCageReceiptBodyV1Bootstrap
ChioCageReceiptBodyV13 = SecurityCageReceiptBodyV1Enforcement
ChioCageReceiptBodyV14 = SecurityCageReceiptBodyV1TerminalExit
SecurityCageReceiptBodyV1ChioCageReceiptBodyV1 = ChioCageReceiptBodyV1
SecurityCageReceiptBodyV1Digest = Digest
SecurityCageReceiptBodyV1Identifier = Identifier
Stage = SecurityCageReceiptBodyV1Stage
