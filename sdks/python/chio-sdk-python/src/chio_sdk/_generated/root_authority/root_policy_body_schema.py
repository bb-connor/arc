# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Parameters(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    inline_fields: list[str]


class Result(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    inline_fields: list[dict[str, Any]]


class CrmSearch(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parameters: Parameters
    result: Result


class Tools(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    crm_search: CrmSearch = Field(..., alias="crm/search")


class Disclosure(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    default: str
    tools: Tools | None = None


class Grant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dpop_required: bool | None = None
    operations: list[str]
    server_id: str
    tool_name: str


class ResourceGrant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operations: list[str]
    uri_pattern: str


class CeilingScope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[Grant]
    resource_grants: list[ResourceGrant] | None = None


class IdpScopeProjection(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    crm_admin: list[str] | None = Field(None, alias="crm.admin")
    crm_read: list[str] = Field(..., alias="crm.read")
    crm_write: list[str] | None = Field(None, alias="crm.write")


class Claims(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    client_id: list[str] | None = None
    scope: list[str] | None = None


class Match(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowed_algs: list[str] | None = None
    anchor_kind: str
    claims: Claims | None = None
    provider_identity_digest: str | None = None
    provider_record_id: str | None = None


class RecordedClaims(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    client_id: str | None = None
    scope: str | None = None


class Rule(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_ttl_secs: int | None = None
    ceiling_scope: CeilingScope
    ceiling_scope_hash: str
    holder_classes: list[str]
    idp_scope_projection: IdpScopeProjection | None = None
    match: Match
    max_assertion_lifetime_secs: int | None = None
    max_clock_skew_secs: int | None = None
    principal: str | None = None
    recorded_claims: RecordedClaims
    retain_idp_artifact: bool | None = None
    rule_id: str
    tenant_value: str | None = None


class ChioRootPolicyV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disclosure: Disclosure | None = None
    exchange_keys: list[str] | None = None
    fixture: str | None = None
    n: int | None = None
    policy_id: str | None = None
    policy_key: str | None = None
    rules: list[Rule] | None = None
    schema_: Literal["chio.root-policy.v1"] = Field(
        "chio.root-policy.v1", alias="schema"
    )
    valid_from: int | None = None
    valid_until: int | None = None
