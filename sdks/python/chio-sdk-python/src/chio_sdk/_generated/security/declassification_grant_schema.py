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

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class Digest32Item(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class Digest32(RootModel[list[Digest32Item]]):
    root: Annotated[list[Digest32Item], Field(max_length=32, min_length=32)]


class FlowIdentifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            max_length=256,
            min_length=1,
            pattern="^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        ),
    ]


class TargetLabel(BaseModel):
    kind: Literal["known"]


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agent_id: FlowIdentifier
    authority_key_id: FlowIdentifier
    capability_id: FlowIdentifier
    destination_id: FlowIdentifier
    domain_version: Literal[1]
    expires_at_unix_seconds: Annotated[int, Field(ge=0)]
    grant_id: FlowIdentifier
    issued_at_unix_seconds: Annotated[int, Field(ge=0)]
    purpose: FlowIdentifier
    request_hash: Digest32
    session_id: FlowIdentifier
    source_label_hash: Digest32
    subject_id: FlowIdentifier
    target_label: TargetLabel
    tenant_id: FlowIdentifier
    tool_name: FlowIdentifier


class SignedDeclassificationGrant(BaseModel):
    """
    One-shot, destination-bound authorization to lower the information label of one exact tool invocation.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    algorithm: Algorithm
    authority_key: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
    body: Body
    signature: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
