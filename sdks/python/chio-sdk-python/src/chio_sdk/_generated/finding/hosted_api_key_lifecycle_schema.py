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


class Operation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activeFrom: int | None = None
    allowedActions: list[str] | None = None
    expiresAt: int | None = None
    kind: str
    principalId: str | None = None
    rotatedFromKeyId: str | None = None


class ChioFindingHostedApiKeyLifecycleSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    eventId: str
    keyId: str
    occurredAt: int
    operation: Operation
    schema_: Literal["chio.finding.hosted-api-key-lifecycle.v1"] = Field(
        ..., alias="schema"
    )
    tenantId: str
