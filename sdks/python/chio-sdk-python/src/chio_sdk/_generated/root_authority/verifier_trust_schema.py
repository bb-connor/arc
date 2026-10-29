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

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from . import root_anchor_schema


class RequiredColumn(Enum):
    identity_root = "identity_root"
    delegation_chain = "delegation_chain"
    decision = "decision"
    content = "content"
    settlement = "settlement"


class ChioVerifierTrust(BaseModel):
    """
    `chio.verifier-trust.v1`: a local, unsigned file the verifying party writes and controls. It pins the keys a verifier accepts and the report columns that must be `verified`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.verifier-trust.v1"] = Field(..., alias="schema")
    kernel_keys: list[root_anchor_schema.PublicKeyHex] = Field(
        ..., max_length=64, min_length=1
    )
    exchange_keys: list[root_anchor_schema.PublicKeyHex] = Field(
        ..., max_length=64, min_length=1
    )
    root_policy_keys: list[root_anchor_schema.PublicKeyHex] = Field(
        ..., max_length=64, min_length=1
    )
    idp_keys: dict[str, list[root_anchor_schema.Jwk]] | None = Field(
        None,
        description="Issuer to the identity-provider keys the verifier pins itself.",
    )
    pep_keys: dict[str, root_anchor_schema.PublicKeyHex] | None = Field(
        None, description="Policy enforcement point id to its pinned key."
    )
    checkpoint_keys: list[root_anchor_schema.PublicKeyHex] | None = Field(
        None, max_length=64
    )
    required_columns: list[RequiredColumn] | None = Field(None, max_length=5)
