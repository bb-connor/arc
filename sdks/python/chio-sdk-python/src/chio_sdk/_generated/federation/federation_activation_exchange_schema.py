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

from pydantic import BaseModel, ConfigDict, Field


class ActivationRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactId: str
    kind: str
    operatorId: str
    schema_: str = Field(..., alias="schema")
    sha256: str
    uri: str


class DelegationControl(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attenuationRequired: bool
    delegateOperatorId: str
    delegatorOperatorId: str
    maxHops: int
    visibilityOnlyUntilLocalActivation: bool


class GoverningCharterRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactId: str
    kind: str
    operatorId: str
    schema_: str = Field(..., alias="schema")
    sha256: str
    uri: str


class ImportControl(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowVisibilityWithoutRuntimeTrust: bool
    explicitLocalActivationRequired: bool
    manualReviewRequired: bool
    prohibitAmbientRuntimeAdmission: bool
    rejectStaleInputs: bool


class ListingRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactId: str
    kind: str
    operatorId: str
    schema_: str = Field(..., alias="schema")
    sha256: str
    uri: str


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowedActorKinds: list[str]
    allowedAdmissionClasses: list[str]
    namespace: str
    policyReference: str
    subjectOperatorId: str


class ChioFederationActivationExchangeSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activationRef: ActivationRef
    delegationControl: DelegationControl
    exchangeId: str
    expiresAt: int
    governingCharterRef: GoverningCharterRef
    importControl: ImportControl
    issuedAt: int
    listingId: str
    listingRef: ListingRef
    note: str
    schema_: Literal["chio.federation-activation-exchange.v1"] = Field(
        ..., alias="schema"
    )
    scope: Scope
    sourceOperatorId: str
    targetOperatorId: str
