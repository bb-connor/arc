# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: c785132ff35c3027a919bab8b2f95d9c699e261d1d605caa42de4f73aa106e19
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
