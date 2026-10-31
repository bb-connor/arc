# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChioSwarmContinuationTokenV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    budgetAllocationId: str
    childTaskId: str
    expiresAtUnixMs: int
    graphId: str
    graphSha256: str
    issuedAtUnixMs: int
    issuer: str
    joinReceiptId: str | None = None
    mode: str
    nonce: str
    parentReceiptIds: list[str]
    parentTaskId: str | None = None
    revocationEpochRef: str
    revocationEpochRootHash: str
    routePlanReceiptId: str
    schema_: Literal["chio.swarm.continuation-token.v1"] = Field(..., alias="schema")
    sessionAnchorRef: str
    tokenId: str
    witnessChainRef: str | None = None
    witnessChainSha256: str | None = None
