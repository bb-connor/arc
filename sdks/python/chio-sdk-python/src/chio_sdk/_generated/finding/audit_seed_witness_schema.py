# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7c51d7910f0345879134e0bf5bbb042abd7b8dbfdcd23700753b77f6814a0f36
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ChioFindingAuditSeedWitnessSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audit_authority: str
    eligible_snapshot_at: int
    eligible_snapshot_digest: str
    epoch_index: int
    seed_commitment: str
    seed_witnessed_at: int
