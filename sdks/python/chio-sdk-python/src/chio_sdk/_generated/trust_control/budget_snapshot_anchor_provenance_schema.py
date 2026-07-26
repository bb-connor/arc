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

from typing import Annotated, Literal

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, RootModel


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Commitment(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anchorSetDigest: Digest
    chainDigest: Digest
    commitSequence: Annotated[int, Field(ge=1)]
    committedAt: Annotated[int, Field(ge=0)]
    electionTerm: Annotated[int, Field(ge=1)]
    leaderUrl: AnyUrl
    previousChainDigest: Digest
    schema_: Annotated[
        Literal["chio.budget-snapshot-anchor-commitment.v1"], Field(alias="schema")
    ]
    signerPublicKey: Annotated[str, Field(min_length=1)]


class SignedCommitment(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Commitment
    signature: Annotated[str, Field(min_length=1)]


class BudgetSnapshotAnchorProvenance(BaseModel):
    """
    Leader-signed inclusion chain authenticating the exact immutable migration-anchor set carried by a trust-control cluster budget snapshot.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    chain: Annotated[list[SignedCommitment], Field(min_length=1)]
    clusterAuthenticator: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    schema_: Annotated[
        Literal["chio.budget-snapshot-anchor-provenance.v1"], Field(alias="schema")
    ]
