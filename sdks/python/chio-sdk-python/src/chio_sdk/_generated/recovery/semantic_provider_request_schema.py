# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: dddda9292ac892d95b9c06f77c067304ba7529e49eddd46850a728e4a94812c6
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, RootModel, constr

from . import semantic_payload_schema


class Kind(Enum):
    support_read = "support_read"
    issue_write = "issue_write"
    field_projection = "field_projection"


class OpaqueId(
    RootModel[
        constr(
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
        )
    ]
):
    root: constr(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
    )


class SemanticProviderRequestV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    domain_version: Literal[1]
    kind: Kind
    provider: OpaqueId
    account: OpaqueId
    resource: OpaqueId
    provider_version: constr(min_length=1, max_length=128)
    operation: OpaqueId
    attempt: constr(min_length=1, max_length=128)
    payload: semantic_payload_schema.SemanticPayloadV1
