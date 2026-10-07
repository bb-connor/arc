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

class Hash(RootModel[constr(pattern='^0x[0-9a-f]{64}$')]):
    root: constr(pattern='^0x[0-9a-f]{64}$')

class ChioKeyLogCheckpointBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.key-log.checkpoint.v1'] = Field(..., alias='schema')
    log_id: constr(pattern='^[A-Za-z0-9._:/-]+$', min_length=1, max_length=128)
    checkpoint_sequence: conint(ge=0)
    tree_size: conint(ge=1)
    root_hash: Hash
    previous_checkpoint_hash: Hash | None = None
    issued_at: conint(ge=0)

# Public compatibility aliases reference the actual current model classes.
SecurityKeyLogCheckpointBodyV1ChioKeyLogCheckpointBodyV1 = ChioKeyLogCheckpointBodyV1
SecurityKeyLogCheckpointBodyV1Hash = Hash
