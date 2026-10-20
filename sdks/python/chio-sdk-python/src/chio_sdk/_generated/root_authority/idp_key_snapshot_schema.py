# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f9c25e1eb1ce1c8ea4083ef04968d45682cd9f79d853175aac0d03e295257b73
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, conint, constr

from . import root_anchor_schema


class ChioIdpKeySnapshot(BaseModel):
    """
    `chio.idp-key-snapshot.v1`, signed by the exchange key. It records the key set the exchange fetched for an enterprise provider record, or took from the record's inline `jwks`, and is in force from `observed_at` until the next snapshot for the same issuer. It is the provider's statement of what the identity provider published, not identity-provider evidence.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.idp-key-snapshot.v1"] = Field(..., alias="schema")
    issuer: root_anchor_schema.Uri
    source: root_anchor_schema.HttpsUrl | constr(
        pattern=r"^registry:[^\u0000\s]{1,128}$", max_length=137
    ) = Field(
        ...,
        description="The record's `jwks_url`, or `registry:<provider_id>` for a record with an inline `jwks`.",
    )
    keys: list[root_anchor_schema.Jwk] = Field(..., max_length=64)
    observed_at: conint(ge=0)
    exchange_key: root_anchor_schema.PublicKeyHex
    signature: root_anchor_schema.SignatureHex
