# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b55a701e44e8cab56a79619656a773cbb3b9fd63c65594e997f7efc988bc178c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Key(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    alg: str | None = None
    crv: str | None = None
    e: str | None = None
    kid: str
    kty: str
    n: str | None = None
    use: str | None = None
    x: str | None = None
    y: str | None = None


class ChioIdpKeySnapshotV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    exchange_key: str | None = None
    fixture: str | None = None
    issuer: str | None = None
    keys: list[Key] | None = None
    n: int | None = None
    observed_at: int | None = None
    schema_: Literal["chio.idp-key-snapshot.v1"] = Field(
        "chio.idp-key-snapshot.v1", alias="schema"
    )
    source: str | None = None
