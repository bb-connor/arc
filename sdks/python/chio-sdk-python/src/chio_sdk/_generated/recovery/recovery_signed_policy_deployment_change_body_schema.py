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
