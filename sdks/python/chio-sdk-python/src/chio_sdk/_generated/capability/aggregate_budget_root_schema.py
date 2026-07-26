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

from pydantic import BaseModel, ConfigDict, Field, RootModel


class AggregateRootPublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class AggregateRootSignature(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class AggregateRootSigningAlgorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: Annotated[int, Field(ge=0, le=4294967295)]
    root_capability_hash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    root_capability_id: Annotated[str, Field(min_length=1)]
    root_expires_at: Annotated[int, Field(ge=0)]
    root_issuer: AggregateRootPublicKey
    root_scope_hash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    root_subject: AggregateRootPublicKey
    schema_: Annotated[Literal["chio.aggregate-budget-root.v1"], Field(alias="schema")]


class ChioAggregateBudgetRootBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    algorithm: AggregateRootSigningAlgorithm | None = None
    body: Body
    signature: AggregateRootSignature
