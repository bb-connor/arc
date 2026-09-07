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

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


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


class Identifiers(RootModel[list[Identifier]]):
    root: list[Identifier] = Field(..., max_length=64, min_length=1)


class Time(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class ChioCorrelatedFindingV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    finding_id: Identifier
    tenant_id: Identifier
    rule_id: Identifier
    rule_version_hash: Digest
    policy_version: Identifier
    group_key_hash: Digest
    ordered_event_ids: Identifiers
    ordered_evidence_digests: list[Digest] = Field(..., max_length=64, min_length=1)
    ordered_source_receipt_ids: Identifiers
    first_event_time_unix_ms: Time
    last_event_time_unix_ms: Time
    lineage_seed: Identifier
