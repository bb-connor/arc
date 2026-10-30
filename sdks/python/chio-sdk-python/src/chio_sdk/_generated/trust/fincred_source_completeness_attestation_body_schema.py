# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cdaf59925a71448dee294bc7dd11837a988bac5f39ad022834183bd6833707a0
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, constr


class AuditPathItem(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class IndexProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    auditPath: list[AuditPathItem] = Field(..., max_length=64)
    leafIndex: int
    treeSize: int


class QueryKey(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactId: str
    occurredAt: int
    sourceFamily: str
    subject: str


class Leaf(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    index: int
    queryKey: QueryKey
    sourceArtifactDigest: str


class CommittedLeaf(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    indexProof: IndexProof
    leaf: Leaf


class LowerBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str


class UpperBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str


class Window(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    endsAt: int
    startsAt: int


class ChioFincredSourceCompletenessAttestationV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attestationReference: str
    checkpointAuthorityEpoch: int
    checkpointAuthorityKey: str
    checkpointDigest: str
    checkpointSequence: int
    committedLeaves: list[CommittedLeaf]
    cutoff: int
    disclosureDigest: str
    expiresAt: int
    indexRoot: str
    issuedAt: int
    lowerBoundary: LowerBoundary
    rangeRoot: str
    schema_: Literal["chio.fincred.source-completeness-attestation.v1"] = Field(
        ..., alias="schema"
    )
    sourceArtifactDigests: list[str]
    sourceEvidenceClass: str
    sourceFamily: str
    sourceId: str
    sourceSignerKey: str
    storeGeneration: int
    subject: str
    upperBoundary: UpperBoundary
    window: Window
