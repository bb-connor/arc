# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 98badc519c6787931e288dad66023f0515a7bda8b0be5b4370b5b906713f8c3e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from chio_sdk._manifest_wire import SecurityWireModel as BaseModel

from pydantic import ConfigDict

from ..capability import threshold_approval_proposal_schema


class ChioToolcallresultPendingApproval(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["pending_approval"]
    proposal: threshold_approval_proposal_schema.ChioThresholdApprovalProposal
