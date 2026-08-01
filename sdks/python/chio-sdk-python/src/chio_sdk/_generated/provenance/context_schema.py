# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class ChioProvenanceCallChainContext(BaseModel):
    """
    One delegated call-chain context bound into a governed Chio request. The context names the stable `chainId` that identifies the delegated transaction, the upstream `parentRequestId` inside the trusted domain, the optional `parentReceiptId` when the upstream parent receipt is already available, the root `originSubject` that started the chain, and the immediate `delegatorSubject` that handed control to the current subject. Chio binds this shape into governed transactions and promotes it through the provenance evidence classes (`asserted`, `observed`, `verified`) defined in `crates/core/chio-core-types` (`GovernedProvenanceEvidenceClass`). Mirrors the `GovernedCallChainContext` struct in `crates/core/chio-core-types`. The struct uses `serde(rename_all = camelCase)` so wire field names are camelCase.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    chainId: Annotated[
        str,
        Field(
            description="Stable identifier for the delegated transaction or call chain. Constant for the duration of the chain; bound into every receipt the chain produces.",
            min_length=1,
        ),
    ]
    delegatorSubject: Annotated[
        str,
        Field(
            description="Immediate delegator subject that handed control to the current subject. Distinct from `originSubject` for chains longer than one hop.",
            min_length=1,
        ),
    ]
    originSubject: Annotated[
        str,
        Field(
            description="Root or originating subject for the governed chain (the subject that started the delegation, expressed in the same canonical form as capability subject keys).",
            min_length=1,
        ),
    ]
    parentReceiptId: Annotated[
        str | None,
        Field(
            description="Optional upstream parent receipt identifier when the parent receipt is already available. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent. When present, Chio can promote the context from `asserted` to `observed` or `verified` by matching it against `LocalParentReceiptLinkage` evidence.",
            min_length=1,
        ),
    ] = None
    parentRequestId: Annotated[
        str,
        Field(
            description="Upstream parent request identifier inside the trusted domain. Used to thread the call into the upstream session lineage.",
            min_length=1,
        ),
    ]
