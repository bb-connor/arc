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

from pydantic import BaseModel, ConfigDict


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_domain: str
    process_id: str
    tenant_id: str


class ChioRecoverySignedPolicyDeploymentChangeV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    base_deployment: list[int]
    base_generation: int
    base_policy: list[int]
    domain_version: int
    proposal_digest: list[int]
    proposal_id: str
    scope: Scope
    target_deployment: list[int]
    target_generation: int
    target_policy: list[int]
    writer_fence: list[int]
