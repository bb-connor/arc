# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: e7734a10ce3d0e21e8497fad86bfb2a97e79c44ce827e678a869c592687f8837
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

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


class Policy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    policy_hash: Digest
    policy_version: Identifier


class Time(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=9007199254740991)]


class Header(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    occurred_at_unix_ms: Time
    prior_receipt_ids: Annotated[list[Identifier], Field(max_length=64)]
    schema_version: Literal[1]
    tenant_id: Identifier
    transition_id: Identifier


class ChioFlowDenialReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    denial_code: Identifier
    destination_label_hash: Digest
    event_id: Identifier
    guard_evidence_hash: Digest
    header: Header
    policy: Policy
    request_hash: Digest
    source_label_hash: Digest
