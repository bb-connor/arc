# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 762578c96088419938225c2c4b88fbd19c43eb893686e68295264db18417432d
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from . import root_anchor_schema


class Kind(Enum):
    """
    Record kinds a root policy rule may reference. `scim` and `saml` records are never referenced.
    """

    oidc_jwks = "oidc_jwks"
    oauth_introspection = "oauth_introspection"


class SubjectMapping(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    principal_source: root_anchor_schema.Identifier = Field(
        ...,
        description="The one claim that is the principal (`oid` for Entra records).",
    )
    tenant_id_field: root_anchor_schema.Identifier = Field(
        ...,
        description="The tenant claim (`iss` for per-organization issuers, `tid` for Entra); it feeds the tenant tag.",
    )


class InlineJwks(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    keys: list[root_anchor_schema.Jwk] = Field(..., max_length=64, min_length=1)


class ChioEnterpriseProviderIdentity(BaseModel):
    """
    `chio.enterprise-provider-identity.v1`: the unsigned, content-addressed identity projection of one enterprise provider record. A root policy rule pins `SHA-256("chio.enterprise-provider-identity.v1\0" || canonical_json(projection))` as `provider_identity_digest`. The projection excludes `enabled`, other provenance labels and validation errors. Decoding is strict.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.enterprise-provider-identity.v1"] = Field(
        ..., alias="schema"
    )
    provider_id: root_anchor_schema.Identifier
    kind: Kind = Field(
        ...,
        description="Record kinds a root policy rule may reference. `scim` and `saml` records are never referenced.",
    )
    issuer: root_anchor_schema.Uri
    jwks_url: root_anchor_schema.HttpsUrl | None = None
    jwks: InlineJwks | None = None
    introspection_url: root_anchor_schema.HttpsUrl | None = None
    audiences: list[root_anchor_schema.Uri] = Field(
        ...,
        description="The record's `trust_boundary.allowed_audiences`.",
        max_length=32,
    )
    subject_mapping: SubjectMapping
    trust_material_ref: root_anchor_schema.Identifier
