# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: eb3605a1594254370980dcf328ad3f0c7a751ff746d1530b9981c40163f5694a
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
