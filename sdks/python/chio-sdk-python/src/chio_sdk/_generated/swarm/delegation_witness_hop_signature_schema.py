# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29e7de509b9e808e1385895b2caf534b995fb61bf99b87fab79bedc072f5a842
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SubsetRelation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    childIndex: int
    grantKind: str
    parentIndex: int
    subset: bool


class ScopeSubsetProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    normalizedChildScope: str
    normalizedParentScope: str
    subsetRelations: list[SubsetRelation]


class ChioSwarmDelegationWitnessHopSignatureSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attenuationRuleId: str
    chainId: str
    childCapabilityDigest: str
    childScopeHash: str
    childTaskId: str
    expiresAtUnixMs: int
    graphId: str
    issuer: str
    parentCapabilityDigest: str
    parentScopeHash: str
    parentTaskId: str
    policyDigest: str
    schema_: Literal["chio.swarm.delegation-witness-hop-signature.v1"] = Field(
        ..., alias="schema"
    )
    scopeSubsetProof: ScopeSubsetProof
