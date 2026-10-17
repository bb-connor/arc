# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 474bdbf3f47de4760cd26c431403a6dfec83325e15db307cb5fcbf132a6f05dd
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from chio_sdk._manifest_wire import SecurityWireModel as BaseModel

from pydantic import ConfigDict, Field, constr


class ChioOpaqueSupplementalAuthorization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    signed_extension: constr(min_length=4, max_length=87384) = Field(
        ...,
        description="Opaque authenticated extension bytes. Adapters must not interpret these bytes as quota authority.",
    )
