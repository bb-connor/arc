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

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, RootModel


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


class Identifiers(RootModel[list[Identifier]]):
    root: Annotated[list[Identifier], Field(max_length=64, min_length=1)]


class Time(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=9007199254740991)]


class ChioCorrelatedFindingV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    finding_id: Identifier
    first_event_time_unix_ms: Time
    group_key_hash: Digest
    last_event_time_unix_ms: Time
    lineage_seed: Identifier
    ordered_event_ids: Identifiers
    ordered_evidence_digests: Annotated[
        list[Digest], Field(max_length=64, min_length=1)
    ]
    ordered_source_receipt_ids: Identifiers
    policy_version: Identifier
    rule_id: Identifier
    rule_version_hash: Digest
    tenant_id: Identifier
