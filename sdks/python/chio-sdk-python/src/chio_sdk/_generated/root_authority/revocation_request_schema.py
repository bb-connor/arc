# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7bc9c9d39014b0d2234c7f929e827c2ab02e825f9cb23c608c135695ce3ed4d1
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, conint, constr

from . import root_anchor_schema


class ChioRevocationRequest(BaseModel):
    """
    `chio.revocation-request.v1` (PROTOCOL 5.6.7), signed by `revoker_key` over the signing wrapper. A caller asks the provider to revoke one of its own delegated descendants; `revoker_key` must be the subject of a strict ancestor of the target in the presentation named by `presentation_digest`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.revocation-request.v1"] = Field(..., alias="schema")
    target_capability_id: constr(min_length=1)
    revoker_key: root_anchor_schema.PublicKeyHex
    presentation_digest: root_anchor_schema.Digest
    reason: constr(min_length=1, max_length=256)
    issued_at: conint(ge=0)
    signature: root_anchor_schema.SignatureHex
