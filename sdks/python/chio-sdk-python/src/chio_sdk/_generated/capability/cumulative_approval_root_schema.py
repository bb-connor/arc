# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class CumulativeRootMonetaryAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: Annotated[str, Field(min_length=1)]
    units: Annotated[int, Field(ge=0)]


class CumulativeRootPublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class CumulativeRootSignature(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class CumulativeRootSigningAlgorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_budget_epoch: Annotated[int, Field(ge=0)]
    approval_budget_id: Annotated[str, Field(min_length=1)]
    root_capability_hash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    root_capability_id: Annotated[str, Field(min_length=1)]
    root_expires_at: Annotated[int, Field(ge=0)]
    root_grant_hash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    root_issuer: CumulativeRootPublicKey
    root_scope_hash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    root_subject: CumulativeRootPublicKey
    schema_: Annotated[
        Literal["chio.cumulative-approval-root.v1"], Field(alias="schema")
    ]
    signer_key_epoch: Annotated[int, Field(ge=0)]
    threshold: CumulativeRootMonetaryAmount


class ChioCumulativeApprovalRootBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    algorithm: CumulativeRootSigningAlgorithm | None = None
    body: Body
    signature: CumulativeRootSignature
