# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from . import cage_receipt_body_v1_schema


class ChioCageReceiptMetadataV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cage_receipt: cage_receipt_body_v1_schema.ChioCageReceiptBodyV1
    schema_: Annotated[Literal["chio.cage.receipt-metadata.v1"], Field(alias="schema")]
