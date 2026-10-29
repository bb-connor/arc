# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class FeeScheduleRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactId: str
    kind: str
    operatorId: str
    schema_: str = Field(..., alias="schema")
    sha256: str
    uri: str | None = None


class GoverningCharterRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactId: str
    kind: str
    operatorId: str
    schema_: str = Field(..., alias="schema")
    sha256: str
    uri: str | None = None


class MinimumBondAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class StakeRequirement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admissionClass: str
    governanceCaseRequired: bool
    minimumBondAmount: MinimumBondAmount
    requiredBondClass: str
    slashable: bool


class ChioFederationOpenAdmissionPolicySignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowedAdmissionClasses: list[str]
    explicitLocalReviewRequired: bool
    feeScheduleRef: FeeScheduleRef
    governingCharterRef: GoverningCharterRef
    governingOperatorId: str
    issuedAt: int
    namespace: str
    note: str | None = None
    policyId: str
    schema_: Literal["chio.federation-open-admission-policy.v1"] = Field(
        ..., alias="schema"
    )
    stakeRequirements: list[StakeRequirement] | None = None
    visibilityOnlyWithoutActivation: bool
