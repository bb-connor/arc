# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7bc9c9d39014b0d2234c7f929e827c2ab02e825f9cb23c608c135695ce3ed4d1
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..capability import token_schema
from . import root_anchor_schema


class RecordedClaims(Enum):
    plain = "plain"
    committed = "committed"


class Claim(RootModel[constr(min_length=1)]):
    root: constr(min_length=1)


class RootPolicyMatch(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anchor_kind: root_anchor_schema.AnchorKind
    issuer: constr(min_length=1)
    jwks_uri: constr(pattern=r"^https://[^\s]+$") | None = Field(
        None,
        description="Required for every JWKS-verified kind. Keys are fetched only from it.",
    )
    allowed_algs: list[root_anchor_schema.JwsAlgorithm] | None = Field(
        None, min_length=1
    )
    claims: dict[str, list[Claim]] | None = Field(
        None, description="Claim name to the values it must take for the rule to match."
    )


class InlineField(RootModel[constr(pattern=r"^(/([^~/]|~[01])*)+$")]):
    root: constr(pattern=r"^(/([^~/]|~[01])*)+$")


class InlineFields(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    inline_fields: list[InlineField]


class ToolDisclosure(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parameters: InlineFields
    result: InlineFields


class RootPolicyDisclosure(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    default: Literal["committed"] = Field(..., description="The only allowed value.")
    tools: dict[str, ToolDisclosure] | None = Field(
        None,
        description="`server/tool` to the RFC 6901 pointers that may appear in plaintext in that tool's receipts. A tool not listed is fully committed.",
    )


class RootPolicyRule(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    rule_id: constr(min_length=1)
    match: RootPolicyMatch
    tenant_claim: constr(min_length=1) | None = Field(
        None,
        description="Claim that identifies the caller's tenant (`iss` for per-organization issuers, `tid` for Entra).",
    )
    idp_scope_projection: dict[str, list[constr(min_length=1)]] | None = Field(
        None,
        description="Identity-provider scope value to the `server/tool` names it projects to. A scope value absent here denies the exchange.",
    )
    ceiling_scope: token_schema.ChioScope
    ceiling_scope_hash: root_anchor_schema.Digest
    recorded_claims: dict[str, RecordedClaims] = Field(
        ...,
        description="Claims copied into the delegation context, each plain or committed.",
    )
    holder_classes: list[root_anchor_schema.HolderClass] = Field(..., min_length=1)
    capability_ttl_secs: conint(ge=1) | None = Field(
        None, description="Defaults to 300."
    )
    max_assertion_lifetime_secs: conint(ge=1) | None = Field(
        None,
        description="Defaults to 300. Absent on `entra_jwt` and `entra_agent_id` rules.",
    )
    max_clock_skew_secs: conint(ge=0, le=60) | None = None
    retain_idp_artifact: bool | None = Field(
        None, description="Allowed only on `oauth_id_jag` rules."
    )
    principal: constr(min_length=1) | None = Field(
        None,
        description="Operator-configured principal. Required on `operator_static_bearer` rules and rejected on every other kind.",
    )
    tenant_value: constr(min_length=1) | None = Field(
        None,
        description="Operator-configured tenant. Required on `operator_static_bearer` rules and rejected on every other kind.",
    )


class ChioRootPolicy(BaseModel):
    """
    `chio.root-policy.v1` (PROTOCOL 5.6.4), signed by the provider's policy key over the signing wrapper. It names the exchange keys, the anchor rules that admit roots and the disclosure policy for committed receipts.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.root-policy.v1"] = Field(..., alias="schema")
    policy_id: constr(min_length=1)
    policy_key: root_anchor_schema.PublicKeyHex = Field(
        ..., description="Must equal the policy key pinned in the edge configuration."
    )
    exchange_keys: list[root_anchor_schema.PublicKeyHex] = Field(..., min_length=1)
    rules: list[RootPolicyRule] = Field(..., min_length=1)
    disclosure: RootPolicyDisclosure
    valid_from: conint(ge=0)
    valid_until: conint(ge=0)
    signature: root_anchor_schema.SignatureHex
