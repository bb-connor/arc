# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b55a701e44e8cab56a79619656a773cbb3b9fd63c65594e997f7efc988bc178c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Claims(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    id: str
    obligationCount: int
    onTimeCount: int
    onTimeRatioBps: int


class CredentialSubject(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claims: Claims
    family: str


class SourceFamily(Enum):
    credit_scorecard = "credit_scorecard"
    exposure_history = "exposure_history"
    settlement_reliability = "settlement_reliability"
    premium_history = "premium_history"
    loss_history = "loss_history"


class Window(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    startsAt: conint(ge=0, le=9007199254740991)
    endsAt: conint(ge=0, le=9007199254740991)


class QueryKey(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    sourceFamily: SourceFamily
    subject: constr(pattern=r"^did:chio:[0-9a-f]{64}$")
    occurredAt: conint(ge=0, le=9007199254740991)
    artifactId: constr(min_length=1, max_length=512)


class Leaf(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    index: conint(ge=0, le=9007199254740991)
    queryKey: QueryKey
    sourceArtifactDigest: constr(pattern=r"^[0-9a-f]{64}$")


class AuditPathItem(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class IndexProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    treeSize: conint(ge=1, le=9007199254740991)
    leafIndex: conint(ge=0, le=9007199254740991)
    auditPath: list[AuditPathItem] = Field(..., max_length=64)


class CommittedLeaf(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    leaf: Leaf
    indexProof: IndexProof


class LowerBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["source_edge"]


class QueryKey2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    sourceFamily: SourceFamily
    subject: constr(pattern=r"^did:chio:[0-9a-f]{64}$")
    occurredAt: conint(ge=0, le=9007199254740991)
    artifactId: constr(min_length=1, max_length=512)


class Leaf3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    index: conint(ge=0, le=9007199254740991)
    queryKey: QueryKey2
    sourceArtifactDigest: constr(pattern=r"^[0-9a-f]{64}$")


class IndexProof2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    treeSize: conint(ge=1, le=9007199254740991)
    leafIndex: conint(ge=0, le=9007199254740991)
    auditPath: list[AuditPathItem] = Field(..., max_length=64)


class LeafProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    leaf: Leaf3
    indexProof: IndexProof2


class LowerBoundary2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["adjacent"]
    leafProof: LeafProof


class UpperBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["source_edge"]


class QueryKey3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    sourceFamily: SourceFamily
    subject: constr(pattern=r"^did:chio:[0-9a-f]{64}$")
    occurredAt: conint(ge=0, le=9007199254740991)
    artifactId: constr(min_length=1, max_length=512)


class Leaf4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    index: conint(ge=0, le=9007199254740991)
    queryKey: QueryKey3
    sourceArtifactDigest: constr(pattern=r"^[0-9a-f]{64}$")


class IndexProof3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    treeSize: conint(ge=1, le=9007199254740991)
    leafIndex: conint(ge=0, le=9007199254740991)
    auditPath: list[AuditPathItem] = Field(..., max_length=64)


class LeafProof1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    leaf: Leaf4
    indexProof: IndexProof3


class UpperBoundary2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["adjacent"]
    leafProof: LeafProof1


class SourceArtifactDigest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class SourceEvidenceClass(Enum):
    asserted = "asserted"
    observed = "observed"
    verified = "verified"


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.fincred.source-completeness-attestation.v1"] = Field(
        ..., alias="schema"
    )
    sourceId: constr(min_length=1, max_length=512)
    sourceFamily: SourceFamily
    subject: constr(pattern=r"^did:chio:[0-9a-f]{64}$")
    sourceSignerKey: constr(pattern=r"^[0-9a-f]{64}$")
    checkpointAuthorityEpoch: conint(ge=1, le=9007199254740991)
    checkpointAuthorityKey: constr(pattern=r"^[0-9a-f]{64}$")
    storeGeneration: conint(ge=1, le=9007199254740991)
    checkpointSequence: conint(ge=1, le=9007199254740991)
    checkpointDigest: constr(pattern=r"^[0-9a-f]{64}$")
    cutoff: conint(ge=0, le=9007199254740991)
    window: Window
    committedLeaves: list[CommittedLeaf] = Field(..., max_length=256, min_length=1)
    rangeRoot: constr(pattern=r"^[0-9a-f]{64}$")
    indexRoot: constr(pattern=r"^[0-9a-f]{64}$")
    lowerBoundary: LowerBoundary | LowerBoundary2
    upperBoundary: UpperBoundary | UpperBoundary2
    sourceArtifactDigests: list[SourceArtifactDigest] = Field(
        ..., max_length=256, min_length=1
    )
    disclosureDigest: constr(pattern=r"^[0-9a-f]{64}$")
    attestationReference: constr(min_length=1, max_length=512)
    issuedAt: conint(ge=0, le=9007199254740991)
    expiresAt: conint(ge=0, le=9007199254740991)
    sourceEvidenceClass: SourceEvidenceClass


class SourceCompletenessAttestation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signerKey: constr(pattern=r"^[0-9a-f]{64}$")
    signature: constr(pattern=r"^[0-9a-f]{128}$")


class Role(Enum):
    claim = "claim"
    member = "member"


class Artifact(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    role: Role
    artifactSchema: constr(min_length=1, max_length=512)
    artifactDigest: constr(pattern=r"^[0-9a-f]{64}$")
    canonicalArtifact: constr(min_length=1, max_length=524288)


class SourceDisclosure(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifacts: list[Artifact] = Field(..., max_length=256)
    kind: str


class Window5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    endsAt: int
    startsAt: int


class Evidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    sourceCompletenessAttestations: list[SourceCompletenessAttestation] = Field(
        ..., max_length=32
    )
    sourceDisclosure: SourceDisclosure
    window: Window5


class ChioFincredSettlementReliabilityV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    field_context: list[str] = Field(..., alias="@context")
    credentialId: str
    credentialSubject: CredentialSubject
    evidence: Evidence
    expirationDate: str
    family: str
    issuanceDate: str
    issuer: str
    issuerKeyEpoch: int
    presentationEvidenceClass: str
    schema_: Literal["chio.fincred.settlement-reliability.v1"] = Field(
        ..., alias="schema"
    )
    sourceEvidenceClass: str
    type: list[str]
