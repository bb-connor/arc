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

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class ChioAggregateFamilyPreservationEvidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    maxInvocations: Annotated[int, Field(ge=0, le=4294967295)]
    rootBindingDigest: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    rootCapabilityId: Annotated[
        str, Field(max_length=512, min_length=1, pattern="^[^\\u0000]+$")
    ]
