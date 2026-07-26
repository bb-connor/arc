# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0a3a1765a96b67781f41c28a0d27ad221b6ab37620da7ca89acc92357927dee9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class CanonicalContributionItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class DigestItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class Digest(RootModel[list[DigestItem]]):
    root: Annotated[list[DigestItem], Field(max_length=32, min_length=32)]


class Identifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            max_length=256,
            min_length=1,
            pattern="^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        ),
    ]


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
    session_id: Identifier
    target_type: Literal["session"]


class Target7(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lineage_id: Identifier
    target_type: Literal["lineage"]


class Target8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    affected_set_hash: Digest
    target_type: Literal["capability_set"]


class Target(RootModel[Target5 | Target6 | Target7 | Target8]):
    root: Target5 | Target6 | Target7 | Target8


class ChioResponseEffectV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    canonical_contribution: Annotated[
        list[CanonicalContributionItem], Field(max_length=1048576)
    ]
    contribution_hash: Digest
    effect_id: Identifier
    kind: Kind
    observed_base_version_hash: Digest
    ordinal: Annotated[int, Field(ge=0, le=65535)]
    target: Target
