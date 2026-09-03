# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 6a4145266d2febc07a862fffbc565f800ff133c6f0adb06aac524c0ff01e4f34
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class FlowIdentifier(
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


class Digest32Item(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class Digest32(RootModel[list[Digest32Item]]):
    root: list[Digest32Item] = Field(..., max_length=32, min_length=32)


class TargetLabel(BaseModel):
    kind: Literal["known"]


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    domain_version: Literal[1]
    grant_id: FlowIdentifier
    capability_id: FlowIdentifier
    tenant_id: FlowIdentifier
    subject_id: FlowIdentifier
    agent_id: FlowIdentifier
    session_id: FlowIdentifier
    source_label_hash: Digest32
    target_label: TargetLabel
    destination_id: FlowIdentifier
    tool_name: FlowIdentifier
    purpose: FlowIdentifier
    request_hash: Digest32
    issued_at_unix_seconds: conint(ge=0)
    expires_at_unix_seconds: conint(ge=0)
    authority_key_id: FlowIdentifier


class SignedDeclassificationGrant(BaseModel):
    """
    One-shot, destination-bound authorization to lower the information label of one exact tool invocation.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    authority_key: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )
    algorithm: Algorithm
    signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )
