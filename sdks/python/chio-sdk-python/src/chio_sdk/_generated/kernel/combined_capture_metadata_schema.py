# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9bba9aeb3efe11ef5ed158d8ad1a12f77957a07c488313f64a3cdf3ffbd36138
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from chio_sdk._manifest_wire import SecurityWireModel as BaseModel

from pydantic import ConfigDict, Field, conint, constr


class QuotaKey(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    profile: constr(min_length=1)
    owner_id: constr(min_length=1)
    grant_index: conint(strict=True, ge=0, le=4294967295) | None = None


class ChioCombinedAdmissionCaptureMetadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.admission-capture-metadata.v1"] = Field(..., alias="schema")
    operation_id: constr(pattern=r"^[0-9a-f]{64}$")
    hold_id: constr(min_length=1)
    quota_keys: list[QuotaKey] = Field(..., max_length=8, min_length=1)
    revocation_set_digest: constr(pattern=r"^[0-9a-f]{64}$")
    budget_commit_index: conint(strict=True, ge=1)
    revocation_commit_index: conint(strict=True, ge=1)
    leader_epoch: conint(strict=True, ge=1)
