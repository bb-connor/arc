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

class SecurityDetectorHealthReceiptBodyV1HealthKind(Enum):
    corrupt_event = 'corrupt_event'
    corrupt_state = 'corrupt_state'
    state_overflow = 'state_overflow'
    store_conflict = 'store_conflict'
    store_unavailable = 'store_unavailable'
    truncated_scan = 'truncated_scan'

class Identifier(RootModel[constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)]):
    root: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

class DigestItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class Digest(RootModel[list[DigestItem]]):
    root: list[DigestItem] = Field(..., max_length=32, min_length=32)

class Time(RootModel[conint(ge=1, le=9007199254740991)]):
    root: conint(ge=1, le=9007199254740991)

class SecurityDetectorHealthReceiptBodyV1DefinitionsHeader(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal[1]
    occurred_at_unix_ms: Time
    tenant_id: Identifier
    transition_id: Identifier
    prior_receipt_ids: list[Identifier] = Field(..., max_length=64)

class SecurityDetectorHealthReceiptBodyV1DefinitionsPolicy(BaseModel):
    model_config = ConfigDict(extra='forbid')
    policy_version: Identifier
    policy_hash: Digest

class SecurityDetectorHealthReceiptBodyV1DefinitionsGroupBindingUnresolved(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unresolved']

class SecurityDetectorHealthReceiptBodyV1DefinitionsGroupBindingResolved(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['resolved']
    group_key_hash: Digest

class GroupBinding(RootModel[SecurityDetectorHealthReceiptBodyV1DefinitionsGroupBindingUnresolved | SecurityDetectorHealthReceiptBodyV1DefinitionsGroupBindingResolved]):
    root: SecurityDetectorHealthReceiptBodyV1DefinitionsGroupBindingUnresolved | SecurityDetectorHealthReceiptBodyV1DefinitionsGroupBindingResolved

class SecurityDetectorHealthReceiptBodyV1DefinitionsWatermarkUnknown(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['unknown']

class SecurityDetectorHealthReceiptBodyV1DefinitionsWatermarkCommitted(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['committed']
    unix_ms: Time

class SecurityDetectorHealthReceiptBodyV1DefinitionsWatermarkContradictory(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['contradictory']
    claimed_unix_ms: constr(pattern='^(0|[1-9][0-9]*)$', min_length=1, max_length=20)

class Watermark(RootModel[SecurityDetectorHealthReceiptBodyV1DefinitionsWatermarkUnknown | SecurityDetectorHealthReceiptBodyV1DefinitionsWatermarkCommitted | SecurityDetectorHealthReceiptBodyV1DefinitionsWatermarkContradictory]):
    root: SecurityDetectorHealthReceiptBodyV1DefinitionsWatermarkUnknown | SecurityDetectorHealthReceiptBodyV1DefinitionsWatermarkCommitted | SecurityDetectorHealthReceiptBodyV1DefinitionsWatermarkContradictory

class ChioDetectorHealthReceiptBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    header: SecurityDetectorHealthReceiptBodyV1DefinitionsHeader
    policy: SecurityDetectorHealthReceiptBodyV1DefinitionsPolicy
    rule_id: Identifier
    rule_version_hash: Digest
    group_binding: GroupBinding
    event_id: Identifier
    health_kind: SecurityDetectorHealthReceiptBodyV1HealthKind
    watermark: Watermark
    evidence_hash: Digest

# Public compatibility aliases reference the actual current model classes.
GroupBinding1 = SecurityDetectorHealthReceiptBodyV1DefinitionsGroupBindingUnresolved
GroupBinding2 = SecurityDetectorHealthReceiptBodyV1DefinitionsGroupBindingResolved
Header = SecurityDetectorHealthReceiptBodyV1DefinitionsHeader
HealthKind = SecurityDetectorHealthReceiptBodyV1HealthKind
Policy = SecurityDetectorHealthReceiptBodyV1DefinitionsPolicy
SecurityDetectorHealthReceiptBodyV1ChioDetectorHealthReceiptBodyV1 = ChioDetectorHealthReceiptBodyV1
SecurityDetectorHealthReceiptBodyV1Digest = Digest
SecurityDetectorHealthReceiptBodyV1DigestItem = DigestItem
SecurityDetectorHealthReceiptBodyV1GroupBinding = GroupBinding
SecurityDetectorHealthReceiptBodyV1Identifier = Identifier
SecurityDetectorHealthReceiptBodyV1Time = Time
SecurityDetectorHealthReceiptBodyV1Watermark = Watermark
Watermark1 = SecurityDetectorHealthReceiptBodyV1DefinitionsWatermarkUnknown
Watermark2 = SecurityDetectorHealthReceiptBodyV1DefinitionsWatermarkCommitted
Watermark3 = SecurityDetectorHealthReceiptBodyV1DefinitionsWatermarkContradictory
