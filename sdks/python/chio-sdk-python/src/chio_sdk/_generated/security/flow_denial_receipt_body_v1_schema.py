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
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

class Identifier(RootModel[constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)]):
    root: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

class DigestItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class Digest(RootModel[list[DigestItem]]):
    root: list[DigestItem] = Field(..., max_length=32, min_length=32)

class Time(RootModel[conint(ge=1, le=9007199254740991)]):
    root: conint(ge=1, le=9007199254740991)

class SecurityFlowDenialReceiptBodyV1DefinitionsHeader(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal[1]
    occurred_at_unix_ms: Time
    tenant_id: Identifier
    transition_id: Identifier
    prior_receipt_ids: list[Identifier] = Field(..., max_length=64)

class SecurityFlowDenialReceiptBodyV1DefinitionsPolicy(BaseModel):
    model_config = ConfigDict(extra='forbid')
    policy_version: Identifier
    policy_hash: Digest

class ChioFlowDenialReceiptBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    header: SecurityFlowDenialReceiptBodyV1DefinitionsHeader
    policy: SecurityFlowDenialReceiptBodyV1DefinitionsPolicy
    request_hash: Digest
    source_label_hash: Digest
    destination_label_hash: Digest
    guard_evidence_hash: Digest
    denial_code: Identifier
    event_id: Identifier

# Public compatibility aliases reference the actual current model classes.
Header = SecurityFlowDenialReceiptBodyV1DefinitionsHeader
Policy = SecurityFlowDenialReceiptBodyV1DefinitionsPolicy
SecurityFlowDenialReceiptBodyV1ChioFlowDenialReceiptBodyV1 = ChioFlowDenialReceiptBodyV1
SecurityFlowDenialReceiptBodyV1Digest = Digest
SecurityFlowDenialReceiptBodyV1DigestItem = DigestItem
SecurityFlowDenialReceiptBodyV1Identifier = Identifier
SecurityFlowDenialReceiptBodyV1Time = Time
