# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7c51d7910f0345879134e0bf5bbb042abd7b8dbfdcd23700753b77f6814a0f36
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Permissions(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    relax: bool
    restrict: bool
    resume: bool
    stop: bool


class Principal(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    permissions: Permissions
    principal: str
    subject_key: str


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str


class Roster(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    principals: list[Principal]
    quorum_k: int
    scope: Scope


class ChioStopOperatorConfigSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_id: str
    config_authority_key: str
    deployment_generation: int
    predecessor_digest: str | None = None
    resume_policy: str
    rosters: list[Roster]
    same_principal_cooldown_ms: int | None = None
    schema_: Literal["chio.stop-operator-config.v1"] = Field(..., alias="schema")
    stop_quorum_max: int
    time_attestation_key: str
