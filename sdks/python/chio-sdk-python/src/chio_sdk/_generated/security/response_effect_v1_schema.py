# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: c56ebd67862c888dd340e0ba3a14bf38d69abc45d8d02e706ed935cd512054ec
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class CanonicalContributionItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class Identifier(
    RootModel[
        constr(
            pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
            min_length=1,
            max_length=256,
        )
    ]
):
    root: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
        max_length=256,
    )


class DigestItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class Digest(RootModel[list[DigestItem]]):
    root: list[DigestItem] = Field(..., max_length=32, min_length=32)


class Kind(Enum):
    escalate_alert = "escalate_alert"
    throttle_session = "throttle_session"
    restrict_egress = "restrict_egress"
    suspend_session = "suspend_session"
    suspend_capability_set = "suspend_capability_set"
    freeze_issuance = "freeze_issuance"


class Target5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    target_type: Literal["tenant"]
    tenant_id: Identifier


class Target6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    target_type: Literal["session"]
    session_id: Identifier


class Target7(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    target_type: Literal["lineage"]
    lineage_id: Identifier


class Target8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    target_type: Literal["capability_set"]
    affected_set_hash: Digest


class Target(RootModel[Target5 | Target6 | Target7 | Target8]):
    root: Target5 | Target6 | Target7 | Target8


class ChioResponseEffectV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effect_id: Identifier
    ordinal: conint(ge=0, le=65535)
    kind: Kind
    target: Target
    canonical_contribution: list[CanonicalContributionItem] = Field(
        ..., max_length=1048576
    )
    contribution_hash: Digest
    observed_base_version_hash: Digest
