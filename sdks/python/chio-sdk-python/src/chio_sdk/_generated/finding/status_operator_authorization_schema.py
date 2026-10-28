# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9040b11ea385ff84e98e4063d81426678eceeb5a4d55e2f86191e7f0064502af
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Operator(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_id: str
    key: str
    key_epoch: int
    revocation_status_ref: str
    rotation_policy_ref: str
    valid_from: int
    valid_until: int


class ChioFindingStatusOperatorAuthorizationSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    feed_id: str
    operator: Operator
    revoked_from: int | None = None
    role: str
