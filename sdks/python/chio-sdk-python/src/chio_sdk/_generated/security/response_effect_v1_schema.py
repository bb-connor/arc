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

class CanonicalContributionItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class Identifier(RootModel[constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)]):
    root: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

class DigestItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class Digest(RootModel[list[DigestItem]]):
    root: list[DigestItem] = Field(..., max_length=32, min_length=32)

class SecurityResponseEffectV1DefinitionsKind(Enum):
    escalate_alert = 'escalate_alert'
    throttle_session = 'throttle_session'
    restrict_egress = 'restrict_egress'
    suspend_session = 'suspend_session'
    suspend_capability_set = 'suspend_capability_set'
    freeze_issuance = 'freeze_issuance'

class SecurityResponseEffectV1DefinitionsTargetVariant0(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_type: Literal['tenant']
    tenant_id: Identifier

class SecurityResponseEffectV1DefinitionsTargetVariant1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_type: Literal['session']
    session_id: Identifier

class SecurityResponseEffectV1DefinitionsTargetVariant2(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_type: Literal['lineage']
    lineage_id: Identifier

class SecurityResponseEffectV1DefinitionsTargetVariant3(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_type: Literal['capability_set']
    affected_set_hash: Digest

class Target(RootModel[SecurityResponseEffectV1DefinitionsTargetVariant0 | SecurityResponseEffectV1DefinitionsTargetVariant1 | SecurityResponseEffectV1DefinitionsTargetVariant2 | SecurityResponseEffectV1DefinitionsTargetVariant3]):
    root: SecurityResponseEffectV1DefinitionsTargetVariant0 | SecurityResponseEffectV1DefinitionsTargetVariant1 | SecurityResponseEffectV1DefinitionsTargetVariant2 | SecurityResponseEffectV1DefinitionsTargetVariant3

class ChioResponseEffectV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    effect_id: Identifier
    ordinal: conint(ge=0, le=65535)
    kind: SecurityResponseEffectV1DefinitionsKind
    target: Target
    canonical_contribution: list[CanonicalContributionItem] = Field(..., max_length=1048576)
    contribution_hash: Digest
    observed_base_version_hash: Digest

# Public compatibility aliases reference the actual current model classes.
Kind = SecurityResponseEffectV1DefinitionsKind
SecurityResponseEffectV1CanonicalContributionItem = CanonicalContributionItem
SecurityResponseEffectV1ChioResponseEffectV1 = ChioResponseEffectV1
SecurityResponseEffectV1Digest = Digest
SecurityResponseEffectV1DigestItem = DigestItem
SecurityResponseEffectV1Identifier = Identifier
SecurityResponseEffectV1Target = Target
Target10 = SecurityResponseEffectV1DefinitionsTargetVariant1
Target11 = SecurityResponseEffectV1DefinitionsTargetVariant2
Target12 = SecurityResponseEffectV1DefinitionsTargetVariant3
Target5 = SecurityResponseEffectV1DefinitionsTargetVariant0
Target6 = SecurityResponseEffectV1DefinitionsTargetVariant1
Target7 = SecurityResponseEffectV1DefinitionsTargetVariant2
Target8 = SecurityResponseEffectV1DefinitionsTargetVariant3
Target9 = SecurityResponseEffectV1DefinitionsTargetVariant0
