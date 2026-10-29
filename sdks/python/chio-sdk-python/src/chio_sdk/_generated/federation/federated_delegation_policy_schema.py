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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ChioFederatedDelegationPolicySignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    createdAt: int
    expiresAt: int
    issuer: str
    parentCapabilityId: str | None = None
    partner: str
    schema_: Literal["chio.federated-delegation-policy.v1"] = Field(..., alias="schema")
    scope: dict[str, Any]
    signerPublicKey: str
    ttlSeconds: int
    verifier: str
