# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b1327961d337a6880e1c267862d3778078a72c85788c98de91fd5bb2d4c74079
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


class InlineField(RootModel[constr(pattern=r"^(/([^~/]|~[01])*)+$", max_length=256)]):
    root: constr(pattern=r"^(/([^~/]|~[01])*)+$", max_length=256)


class InlineFields(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    inline_fields: list[InlineField] = Field(..., max_length=64)


class MatchClaims(BaseModel):
    """
    Claim name to the values it must take for the rule to match. Audience is never matched here; it comes from the provider record.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    client_id: list[root_anchor_schema.Text] | None = Field(
        None, max_length=64, min_length=1
    )
    scope: list[root_anchor_schema.Text] | None = Field(
        None, max_length=64, min_length=1
    )
    sub: list[root_anchor_schema.Text] | None = Field(None, max_length=64, min_length=1)
    resource: list[root_anchor_schema.Text] | None = Field(
        None, max_length=64, min_length=1
    )
    azp: list[root_anchor_schema.Text] | None = Field(None, max_length=64, min_length=1)
    appid: list[root_anchor_schema.Text] | None = Field(
        None, max_length=64, min_length=1
    )
    oid: list[root_anchor_schema.Text] | None = Field(None, max_length=64, min_length=1)
    tid: list[root_anchor_schema.Text] | None = Field(None, max_length=64, min_length=1)


class ClaimMode(Enum):
    plain = "plain"
    committed = "committed"


class RootPolicyMatch(BaseModel):
    """
    What a token must satisfy for the rule to match. Its `iss` must equal the issuer of the named provider record.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    anchor_kind: root_anchor_schema.AnchorKind
    provider_record_id: root_anchor_schema.Identifier | None = Field(
        None,
        description="`provider_id` of the enterprise provider record this rule verifies against. Required for provider-backed kinds and absent otherwise.",
    )
    provider_identity_digest: root_anchor_schema.Digest | None = Field(
        None,
        description='`SHA-256("chio.enterprise-provider-identity.v1\\0" || canonical_json(projection))` over the record\'s identity projection. A record whose projection differs denies.',
    )
    allowed_algs: list[root_anchor_schema.JwsAlgorithm] | None = Field(
        None, max_length=10, min_length=1
    )
    claims: MatchClaims | None = None


class ToolDisclosure(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parameters: InlineFields
    result: InlineFields


class RecordedClaimModes(BaseModel):
    """
    Claims copied into the delegation context, each plain or committed. The claim set is closed.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    client_id: ClaimMode | None = None
    scope: ClaimMode | None = None
    sub: ClaimMode | None = None
    aud: ClaimMode | None = None
    resource: ClaimMode | None = None
    azp: ClaimMode | None = None
    appid: ClaimMode | None = None
    oid: ClaimMode | None = None
    tid: ClaimMode | None = None


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
    rule_id: root_anchor_schema.Identifier
    match: RootPolicyMatch
    idp_scope_projection: dict[str, list[root_anchor_schema.Identifier]] | None = Field(
        None,
        description="Identity-provider scope value to the `server/tool` names it projects to. A scope value absent here denies the exchange.",
    )
    ceiling_scope: token_schema.ChioScope
    ceiling_scope_hash: root_anchor_schema.Digest
    recorded_claims: RecordedClaimModes
    holder_classes: list[root_anchor_schema.HolderClass] = Field(
        ..., max_length=2, min_length=1
    )
    capability_ttl_secs: conint(ge=1, le=86400) | None = Field(
        None, description="Defaults to 300."
    )
    max_assertion_lifetime_secs: conint(ge=1, le=86400) | None = Field(
        None,
        description="Defaults to 300. Absent on `entra_jwt` and `entra_agent_id` rules.",
    )
    max_clock_skew_secs: conint(ge=0, le=60) | None = None
    retain_idp_artifact: bool | None = Field(
        None, description="Allowed only on `oauth_id_jag` rules."
    )
    principal: root_anchor_schema.Identifier | None = Field(
        None,
        description="Operator-configured principal. Required on `operator_static_bearer` rules and rejected on every other kind.",
    )
    tenant_value: root_anchor_schema.Identifier | None = Field(
        None,
        description="Operator-configured tenant. Required on `operator_static_bearer` rules and rejected on every other kind.",
    )


class ChioRootPolicy(BaseModel):
    """
    `chio.root-policy.v1`, signed by the provider's policy key. It names the exchange keys, the anchor rules that admit roots and the disclosure policy for committed receipts. Provider identity (issuer, keys, endpoints, audiences, principal and tenant claims) is never held here: a provider-backed rule names an enterprise provider record and pins the digest of its identity projection. Decoding is strict: an unknown member at any level rejects at load.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.root-policy.v1"] = Field(..., alias="schema")
    policy_id: root_anchor_schema.Identifier
    policy_key: root_anchor_schema.PublicKeyHex = Field(
        ..., description="Must equal the policy key pinned in the edge configuration."
    )
    exchange_keys: list[root_anchor_schema.PublicKeyHex] = Field(
        ..., max_length=16, min_length=1
    )
    rules: list[RootPolicyRule] = Field(..., max_length=64, min_length=1)
    disclosure: RootPolicyDisclosure
    valid_from: conint(ge=0)
    valid_until: conint(ge=0)
    signature: root_anchor_schema.SignatureHex
