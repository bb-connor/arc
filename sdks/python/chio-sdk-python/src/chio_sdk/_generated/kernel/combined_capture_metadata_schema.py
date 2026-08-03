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


class QuotaKey(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grant_index: Annotated[int | None, Field(ge=0, le=4294967295)] = None
    owner_id: Annotated[str, Field(min_length=1)]
    profile: Annotated[str, Field(min_length=1)]


class ChioCombinedAdmissionCaptureMetadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    budget_commit_index: Annotated[int, Field(ge=1)]
    hold_id: Annotated[str, Field(min_length=1)]
    leader_epoch: Annotated[int, Field(ge=1)]
    operation_id: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    quota_keys: Annotated[list[QuotaKey], Field(max_length=8, min_length=1)]
    revocation_commit_index: Annotated[int, Field(ge=1)]
    revocation_set_digest: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    schema_: Annotated[
        Literal["chio.admission-capture-metadata.v1"], Field(alias="schema")
    ]
