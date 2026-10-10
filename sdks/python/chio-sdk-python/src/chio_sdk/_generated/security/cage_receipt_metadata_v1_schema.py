# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: d2b29cbbc9a0070d3666a33fd5a06bbda07a8e70f6d54bf33c15ca8b74893ff9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from . import cage_receipt_body_v1_schema

class ChioCageReceiptMetadataV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.cage.receipt-metadata.v1'] = Field(..., alias='schema')
    cage_receipt: cage_receipt_body_v1_schema.ChioCageReceiptBodyV1

# Public compatibility aliases reference the actual current model classes.
SecurityCageReceiptMetadataV1ChioCageReceiptMetadataV1 = ChioCageReceiptMetadataV1
