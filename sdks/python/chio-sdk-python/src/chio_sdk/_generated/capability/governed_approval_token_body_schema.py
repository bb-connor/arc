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
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Decision(Enum):
    approved = "approved"
    denied = "denied"


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class GovernanceIdentifier(RootModel[str]):
    root: Annotated[str, Field(max_length=256, min_length=1)]


class PublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class ChioGovernedApprovalTokenBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approver: PublicKey
    decision: Decision
    expires_at: Annotated[int, Field(ge=1)]
    governed_intent_hash: Digest
    id: GovernanceIdentifier
    issued_at: Annotated[int, Field(ge=0)]
    request_id: GovernanceIdentifier
    subject: PublicKey
    threshold_proposal_hash: Digest | None = None
