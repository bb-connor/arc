# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29e7de509b9e808e1385895b2caf534b995fb61bf99b87fab79bedc072f5a842
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, constr

from . import revocation_entry_schema


class CapabilityTarget(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["capability_id"]
    capability_id: constr(pattern=r"^[^\u0000]+$", min_length=1, max_length=512) = (
        Field(..., description="The capability to revoke, with every descendant.")
    )


class ChioRevocationAdminRequest(BaseModel):
    """
    Body of `POST /admin/revocations` on a hosted edge: one target and a closed reason, strict at every level. The target is a tagged union on `kind`; this version accepts the `capability_id` kind. The response carries the stored `chio.revocation-entry.v1`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    target: CapabilityTarget
    reason: revocation_entry_schema.RevocationReason
