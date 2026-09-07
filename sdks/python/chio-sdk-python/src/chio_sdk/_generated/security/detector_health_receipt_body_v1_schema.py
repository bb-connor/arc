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


class HealthKind(Enum):
    corrupt_event = "corrupt_event"
    corrupt_state = "corrupt_state"
    state_overflow = "state_overflow"
    store_conflict = "store_conflict"
    store_unavailable = "store_unavailable"
    truncated_scan = "truncated_scan"


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


class Time(RootModel[conint(ge=1, le=9007199254740991)]):
    root: conint(ge=1, le=9007199254740991)


class Header(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal[1]
    occurred_at_unix_ms: Time
    tenant_id: Identifier
    transition_id: Identifier
    prior_receipt_ids: list[Identifier] = Field(..., max_length=64)


class Policy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    policy_version: Identifier
    policy_hash: Digest


class GroupBinding1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unresolved"]


class GroupBinding2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["resolved"]
    group_key_hash: Digest


class GroupBinding(RootModel[GroupBinding1 | GroupBinding2]):
    root: GroupBinding1 | GroupBinding2


class Watermark1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unknown"]


class Watermark2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["committed"]
    unix_ms: Time


class Watermark3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["contradictory"]
    claimed_unix_ms: constr(pattern=r"^(0|[1-9][0-9]*)$", min_length=1, max_length=20)


class Watermark(RootModel[Watermark1 | Watermark2 | Watermark3]):
    root: Watermark1 | Watermark2 | Watermark3


class ChioDetectorHealthReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    header: Header
    policy: Policy
    rule_id: Identifier
    rule_version_hash: Digest
    group_binding: GroupBinding
    event_id: Identifier
    health_kind: HealthKind
    watermark: Watermark
    evidence_hash: Digest
