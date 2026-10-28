# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9040b11ea385ff84e98e4063d81426678eceeb5a4d55e2f86191e7f0064502af
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, conint, constr

from ..capability import governed_approval_token_schema


class Schema(Enum):
    chio_dpop_proof_v1 = "chio.dpop_proof.v1"


class ReplayAuthority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    destination_store_uuid: UUID
    dpop_authority_id: constr(min_length=1, max_length=512)
    expectation_id: constr(pattern=r"^[0-9a-f]{64}$")
    proof_ttl_secs: conint(ge=1, le=3600)
    max_clock_skew_secs: conint(ge=0, le=300)


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Schema = Field(..., alias="schema")
    replay_authority: ReplayAuthority
    capability_id: constr(min_length=1)
    tool_server: constr(min_length=1)
    tool_name: constr(min_length=1)
    action_hash: constr(pattern=r"^[0-9a-f]{64}$")
    nonce: constr(min_length=1)
    issued_at: conint(ge=0, le=18446744073709551615)
    agent_key: governed_approval_token_schema.GovernedApprovalPublicKey


class ChioInvocationProofOfPossession(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    signature: governed_approval_token_schema.GovernedApprovalSignature
    body: Body
