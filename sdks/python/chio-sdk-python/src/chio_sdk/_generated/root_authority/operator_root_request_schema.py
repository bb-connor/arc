# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, conint

from ..capability import token_schema
from . import root_anchor_schema


class ChioOperatorRootRequest(BaseModel):
    """
    `chio.operator-root-request.v1`, signed by the operator key the edge pins. The operator asks the edge for one `chio_operator_key` anchored root for `principal` in `tenant_value`. The signature covers the canonical JSON of every member except `signature`, and `request_id` is the replay key.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.operator-root-request.v1"] = Field(..., alias="schema")
    request_id: root_anchor_schema.Identifier
    principal: root_anchor_schema.Identifier
    tenant_value: root_anchor_schema.Identifier
    scope: token_schema.ChioScope
    holder: root_anchor_schema.HolderClass
    expires_at: conint(ge=0)
    signature: root_anchor_schema.SignatureHex
