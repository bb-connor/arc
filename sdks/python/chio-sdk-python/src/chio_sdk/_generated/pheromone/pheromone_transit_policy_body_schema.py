# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ObservationCostVerifierRoot(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowedSubjectClassNamespaces: list[str]
    allowedSubjectClasses: list[str]
    allowedTreaties: list[str]
    issuerKernelId: str
    issuerSignature: str
    publicKey: str
    runtimePolicySha256: str
    schema_: str = Field(..., alias="schema")
    validFromUnixMs: int
    validUntilUnixMs: int
    verifierId: str
    verifierKeyId: str


class Passport(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    firstSeenEpoch: int
    kernelId: str
    publicKey: str
    revoked: bool
    validFromUnixMs: int
    validUntilUnixMs: int


class Entry(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    highestVersion: int | None = None
    keyId: str
    latestBundleSha256: str | None = None
    latestRevocationCheckpointSha256: str | None = None
    revoked: bool | None = None
    verifierId: str


class RuntimeTrustFloorState(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    entries: list[Entry]
    schema_: str = Field(..., alias="schema")


class ScarcityPolicy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activePeersEpoch: int
    newcomerHorizonEpochs: int | None = None
    observationCostVerification: str
    policyId: str
    policySha256: str | None = None
    reputationEpoch: int
    runtimePolicySha256: str
    schema_: str = Field(..., alias="schema")
    subjectClass: str
    subjectClassNamespace: str
    tokenCapacity: int
    treatyScope: list[str]
    verifierId: str
    windowEndUnixMs: int
    windowId: str
    windowStartUnixMs: int


class SubjectClass(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowedTreaties: list[str]
    costCommitment: str
    destructive: bool
    subjectClass: str
    subjectClassNamespace: str


class Admission(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activePeersInTreaty: int
    activeReputationEpoch: int | None = None
    authenticatedSenderKernelId: str
    implicitCompatibilityDefault: bool | None = None
    kernelPublicKeys: list[str]
    knownReputationEpochs: list[int]
    maxDepositsPerPair: int
    observationCostVerifierRoots: list[ObservationCostVerifierRoot]
    passports: list[Passport]
    recipientKernelId: str
    replayWindowMs: int
    runtimePolicyIssuerPublicKeys: list[str]
    runtimeTrustFloorState: RuntimeTrustFloorState
    scarcityPolicies: list[ScarcityPolicy] | None = None
    subjectClasses: list[SubjectClass]


class PinnedLadderRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ladder_intersection_id: str
    ladder_intersection_sha256: str
    ladder_manifest_expires_at_unix_ms: int
    ladder_manifest_id: str
    ladder_manifest_sha256: str


class ChioPheromoneTransitPolicyV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    accepted_hubs: list[str]
    admission: Admission
    allowed_egress_treaties: list[str]
    allowed_ingress_treaties: list[str]
    allowed_subject_class_namespaces: list[str]
    max_hops: int
    pinned_ladder_refs: list[PinnedLadderRef]
    required_action_class_id: str
    schema_: Literal["chio.pheromone-transit-policy.v1"] = Field(..., alias="schema")
    valid_from_unix_ms: int
    valid_until_unix_ms: int
