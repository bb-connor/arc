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

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class CheckpointId(RootModel[str]):
    root: Annotated[str, Field(min_length=1)]


class Inclusion(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpointId: Annotated[str, Field(min_length=1)]
    leafHash: Annotated[str, Field(pattern="^(0x)?[0-9a-f]{64}$")]
    proof: dict[str, Any]


class Kind(Enum):
    rekor = "rekor"
    ots = "ots"
    solana_memo = "solana_memo"


class Witness(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Kind
    observedAt: Annotated[int | None, Field(ge=0)] = None
    root: Annotated[str, Field(pattern="^(0x)?[0-9a-f]{64}$")]
    witnessId: Annotated[str, Field(min_length=1)]


class WitnessReceipt(BaseModel):
    """
    Verifier-bound receipt returned by a public-witness lane. OTS receipts remain advisory until the lane carries trusted Bitcoin header or calendar-backed commitment evidence.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    bodyHash: Annotated[str, Field(pattern="^(0x)?[0-9a-f]{64}$")]
    externalUuid: Annotated[str, Field(min_length=1)]
    inclusionProof: Annotated[
        str,
        Field(
            pattern="^$|^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
        ),
    ]
    kind: Kind
    publishedAt: Annotated[int, Field(ge=0)]
    witnessRoot: Annotated[str, Field(pattern="^(0x)?[0-9a-f]{64}$")]


class WitnessState1(BaseModel):
    """
    W2.3 lifecycle for the public-witness lane. Defaults to {kind: pending} when omitted to preserve wire compatibility for v1 batches that pre-date the state machine.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["pending"]


class WitnessState2(BaseModel):
    """
    W2.3 lifecycle for the public-witness lane. Defaults to {kind: pending} when omitted to preserve wire compatibility for v1 batches that pre-date the state machine.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["witnessed"]
    observed_at: Annotated[int, Field(ge=0)]
    receipt: WitnessReceipt


class WitnessState3(BaseModel):
    """
    W2.3 lifecycle for the public-witness lane. Defaults to {kind: pending} when omitted to preserve wire compatibility for v1 batches that pre-date the state machine.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    error: Annotated[str, Field(min_length=1)]
    kind: Literal["stale"]
    last_verified: Annotated[int, Field(ge=0)]


class WitnessState(RootModel[WitnessState1 | WitnessState2 | WitnessState3]):
    root: Annotated[
        WitnessState1 | WitnessState2 | WitnessState3,
        Field(
            description="W2.3 lifecycle for the public-witness lane. Defaults to {kind: pending} when omitted to preserve wire compatibility for v1 batches that pre-date the state machine."
        ),
    ]


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpointIds: Annotated[list[CheckpointId], Field(min_length=1)]
    inclusions: Annotated[list[Inclusion], Field(min_length=1)]
    issuedAt: Annotated[int, Field(ge=0)]
    schema_: Annotated[Literal["chio.anchor_batch.v1"], Field(alias="schema")]
    signerKey: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
    treeRoot: Annotated[str, Field(pattern="^(0x)?[0-9a-f]{64}$")]
    witness: Witness
    witnessState: WitnessState | None = None


class ChioAnchorBatchV1(BaseModel):
    """
    Signed additive Merkle batch over receipts or checkpoints. Local receipt signatures remain authoritative; the batch adds continuity and public-witness timestamping.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
