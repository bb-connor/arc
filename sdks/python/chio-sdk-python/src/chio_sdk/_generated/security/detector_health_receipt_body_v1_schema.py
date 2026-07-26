# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    model_serializer,
    model_validator,
)


class HealthKind(Enum):
    corrupt_event = "corrupt_event"
    corrupt_state = "corrupt_state"
    state_overflow = "state_overflow"
    store_conflict = "store_conflict"
    store_unavailable = "store_unavailable"
    truncated_scan = "truncated_scan"


class DigestItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class Digest(RootModel[list[DigestItem]]):
    root: Annotated[list[DigestItem], Field(max_length=32, min_length=32)]


    model_config = ConfigDict(validate_assignment=True)

    @model_validator(mode="after")
    def _reject_zero_digest(self) -> "Digest":
        if all(item.root == 0 for item in self.root):
            raise ValueError("detector health digest must not be all zero")
        return self

class GroupBinding1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unresolved"]


class GroupBinding2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    group_key_hash: Digest
    kind: Literal["resolved"]


class GroupBinding(RootModel[GroupBinding1 | GroupBinding2]):
    root: GroupBinding1 | GroupBinding2


class Identifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            max_length=256,
            min_length=1,
            pattern="^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        ),
    ]


class Policy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    policy_hash: Digest
    policy_version: Identifier


class Time(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=9007199254740991)]


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
    claimed_unix_ms: Annotated[
        str, Field(max_length=20, min_length=1, pattern="^(0|[1-9][0-9]*)$")
    ]
    kind: Literal["contradictory"]


class Watermark(RootModel[Watermark1 | Watermark2 | Watermark3]):
    root: Watermark1 | Watermark2 | Watermark3


class Header(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    occurred_at_unix_ms: Time
    prior_receipt_ids: Annotated[list[Identifier], Field(max_length=64)]
    schema_version: Literal[1]
    tenant_id: Identifier
    transition_id: Identifier


class ChioDetectorHealthReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )
    event_id: Identifier
    evidence_hash: Digest
    group_binding: GroupBinding
    header: Header
    health_kind: HealthKind
    policy: Policy
    rule_id: Identifier
    rule_version_hash: Digest
    watermark: Watermark

    @model_validator(mode="after")
    def _validate_detector_health(self) -> "ChioDetectorHealthReceiptBodyV1":
        group = self.group_binding.root
        group_kind = group.kind
        watermark = self.watermark.root
        watermark_kind = watermark.kind
        observed = self.header.occurred_at_unix_ms.root
        if observed < 1 or observed > 9007199254740991:
            raise ValueError("detector health observation time is outside the portable range")
        digests = (
            self.evidence_hash,
            self.policy.policy_hash,
            self.rule_version_hash,
        )
        if any(all(item.root == 0 for item in digest.root) for digest in digests):
            raise ValueError("detector health digest must not be all zero")
        if group_kind == "resolved" and all(
            item.root == 0 for item in group.group_key_hash.root
        ):
            raise ValueError("resolved detector group hash must not be all zero")
        if group_kind == "unresolved" and watermark_kind != "unknown":
            raise ValueError("unresolved detector group cannot assert watermark knowledge")
        if watermark_kind == "committed":
            committed = watermark.unix_ms.root
            if committed < 1 or committed > 9007199254740991:
                raise ValueError("committed detector watermark is outside the portable range")
            if committed > observed:
                raise ValueError("committed detector watermark is after the observation")
        if watermark_kind == "contradictory":
            if group_kind != "resolved" or self.health_kind is not HealthKind.corrupt_state:
                raise ValueError("contradictory detector watermark requires resolved corrupt state")
            claimed = int(watermark.claimed_unix_ms)
            if claimed > 18446744073709551615:
                raise ValueError("contradictory detector watermark exceeds u64")
            if claimed != 0 and claimed <= observed and claimed <= 9007199254740991:
                raise ValueError("contradictory detector watermark carries a valid committed value")
        return self

    @model_serializer(mode="wrap")
    def _serialize_validated(self, handler):
        self._validate_detector_health()
        return handler(self)
