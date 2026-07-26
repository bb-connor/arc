# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0a3a1765a96b67781f41c28a0d27ad221b6ab37620da7ca89acc92357927dee9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            description="A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.",
            max_length=512,
            min_length=1,
            pattern="^[^\\u0000]+$",
        ),
    ]


class PositiveSafeInteger(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=9007199254740991)]


class PositiveUint32(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=4294967295)]


class Summary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_id: Identifier
    counter_namespace_digest: Digest
    fencing_token: PositiveSafeInteger
    partition_id: Identifier
    resolver_configuration_digest: Digest
    resolver_id: Identifier
    resolver_implementation_id: Identifier
    resolver_implementation_version: PositiveUint32
    store_identity_digest: Digest


class ChioPartitionEscrowFinancialReceiptMetadata(BaseModel):
    """
    Receipt-side partition authority proof carrying the exact canonical admission-evidence JSON, its domain-separated digest, and an indexable authority summary.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    canonical_json: Annotated[
        str,
        Field(
            description="The exact RFC 8785 canonical JSON serialization of a partition-escrow admission evidence object. Runtime validation applies the one MiB bound to UTF-8 bytes.",
            max_length=1048576,
            min_length=1,
        ),
    ]
    evidence_digest: Digest
    summary: Summary
