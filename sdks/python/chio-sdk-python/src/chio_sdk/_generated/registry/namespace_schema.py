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


class Boundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    automaticTrustAdmission: bool
    explicitTrustActivationRequired: bool
    visibilityOnly: bool


class Ownership(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    namespace: str
    ownerId: str
    registeredAt: int
    registryUrl: str
    signerPublicKey: str


class ChioRegistryNamespaceSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    boundary: Boundary
    lifecycleState: str
    namespaceId: str
    ownership: Ownership
    schema_: Literal["chio.registry.namespace.v1"] = Field(..., alias="schema")
