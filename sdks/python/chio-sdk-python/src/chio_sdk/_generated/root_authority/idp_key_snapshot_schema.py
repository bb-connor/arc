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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, conint, constr

from . import root_anchor_schema


class ChioIdpKeySnapshot(BaseModel):
    """
    `chio.idp-key-snapshot.v1` (PROTOCOL 5.6.4), signed by the exchange key over the signing wrapper. It records the key set the exchange fetched from an identity provider and is in force from `observed_at` until the next snapshot for the same issuer. It is the provider's statement, not identity-provider evidence.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.idp-key-snapshot.v1"] = Field(..., alias="schema")
    issuer: constr(min_length=1)
    source: constr(pattern=r"^https://[^\s]+$") = Field(
        ..., description="The pinned `jwks_uri` the keys were fetched from."
    )
    keys: list[root_anchor_schema.Jwk]
    observed_at: conint(ge=0)
    exchange_key: root_anchor_schema.PublicKeyHex
    signature: root_anchor_schema.SignatureHex
