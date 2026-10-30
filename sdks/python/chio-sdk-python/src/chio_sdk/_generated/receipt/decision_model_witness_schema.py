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

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Outcome(Enum):
    allow = "allow"
    hold = "hold"
    deny = "deny"


class Evaluation(Enum):
    evaluated = "evaluated"
    fallback = "fallback"


class FallbackReason(Enum):
    empty_proposal = "empty_proposal"
    proposal_infeasible = "proposal_infeasible"
    scorer_error = "scorer_error"
    work_exhausted = "work_exhausted"
    policy_unavailable = "policy_unavailable"


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class ChioDecisionModelWitnessReceiptMetadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.decision-model-witness.v1"] = Field(..., alias="schema")
    model_card_digest: Digest
    artifact_digest: Digest
    outcome: Outcome
    evaluation: Evaluation
    fallback_reason: FallbackReason | None = None
    work_ops: conint(ge=0, le=4294967295)
