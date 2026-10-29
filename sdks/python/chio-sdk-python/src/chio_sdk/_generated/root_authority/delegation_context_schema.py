# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: dddda9292ac892d95b9c06f77c067304ba7529e49eddd46850a728e4a94812c6
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, conint

from . import root_anchor_schema


class DelegationExchange(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    exchange_key: root_anchor_schema.PublicKeyHex = Field(
        ..., description="Equals the issuer key of the minted root."
    )
    exchanged_at: conint(ge=0)
    request_digest: root_anchor_schema.Digest
    holder: root_anchor_schema.HolderClass


class SubjectCommitment(BaseModel):
    """
    `SHA-256("chio.delegation-context.subject.v1\0" || salt || utf8(subject))`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    commit: root_anchor_schema.Digest
    salt_ref: Literal["anchor.sub"]


class TenantCommitment(BaseModel):
    """
    `SHA-256("chio.delegation-context.tenant.v1\0" || salt || utf8(tenant))`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    commit: root_anchor_schema.Digest
    salt_ref: Literal["anchor.tenant"]


class DelegationAnchor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: root_anchor_schema.AnchorKind
    issuer: root_anchor_schema.Uri = Field(
        ...,
        description="The provider record's issuer for provider-backed kinds; `urn:chio:operator` for `operator_static_bearer`.",
    )
    provider_record_id: root_anchor_schema.Identifier | None = Field(
        None,
        description="The enterprise provider record the exchange verified against. Present exactly for provider-backed kinds.",
    )
    provider_identity_digest: root_anchor_schema.Digest | None = Field(
        None,
        description="Digest of the record's `chio.enterprise-provider-identity.v1` projection; equals the matched rule's. Present exactly for provider-backed kinds.",
    )
    key_snapshot_digest: root_anchor_schema.Digest | None = Field(
        None,
        description="Digest of the `chio.idp-key-snapshot.v1` in force when the assertion was verified.",
    )
    kid: root_anchor_schema.Identifier | None = None
    alg: root_anchor_schema.JwsAlgorithm | None = None
    artifact_digest: root_anchor_schema.Digest | None = Field(
        None, description="SHA-256 of the exact compact JWS bytes received."
    )
    artifact_retained: bool = Field(
        ...,
        description="True only for `oauth_id_jag` under a rule with `retain_idp_artifact: true`.",
    )
    replay_key_digest: root_anchor_schema.Digest
    token_iat: conint(ge=0)
    token_exp: conint(ge=0)
    subject: SubjectCommitment
    tenant: TenantCommitment
    claims: root_anchor_schema.RecordedClaims = Field(
        ...,
        description="Exactly the claims the matched rule names in `recorded_claims`, each plain or committed per the rule.",
    )


class ChioDelegationContext(BaseModel):
    """
    `chio.delegation-context.v1`: the content-addressed, unsigned record of one root exchange. It is bound into the signed root through `root_anchor.context_digest`. Decoding is strict: an unknown member at any level rejects.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.delegation-context.v1"] = Field(..., alias="schema")
    anchor: DelegationAnchor
    exchange: DelegationExchange
    root_policy_rule_id: root_anchor_schema.Identifier = Field(
        ..., description="`rule_id` of the root policy rule that matched."
    )
    effective_root_scope_hash: root_anchor_schema.Digest = Field(
        ..., description="Equals the scope hash of the minted root."
    )
