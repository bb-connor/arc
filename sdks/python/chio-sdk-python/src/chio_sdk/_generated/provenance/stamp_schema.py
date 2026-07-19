# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: e7734a10ce3d0e21e8497fad86bfb2a97e79c44ce827e678a869c592687f8837
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class ChioProvenanceStamp(BaseModel):
    """
    One provenance stamp attached by a Chio provider adapter to every tool-call response. Names the upstream `provider`, the upstream `request_id`, the wire `api_version`, the `principal` Chio resolved as the calling subject, and the unix-second `received_at` timestamp. Field names are snake_case to match `RuntimeAttestationEvidence`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    api_version: Annotated[
        str,
        Field(
            description="Wire version of the upstream provider API that served the call. Free-form per provider (for example `2024-08-01-preview` for Azure OpenAI, `v1` for Anthropic). Frozen per stamp; bumps require a new stamp.",
            min_length=1,
        ),
    ]
    principal: Annotated[
        str,
        Field(
            description="Calling subject Chio resolved at the kernel boundary, in the same canonical form used by capability tokens (subject public key or normalized workload identity). Bound into the provenance graph alongside the receipt principal.",
            min_length=1,
        ),
    ]
    provider: Annotated[
        str,
        Field(
            description="Stable identifier of the upstream provider adapter that handled the tool call (for example `openai`, `anthropic`, `google-vertex`).",
            min_length=1,
        ),
    ]
    received_at: Annotated[
        int,
        Field(
            description="Unix timestamp (seconds) at which Chio observed the provider response. Monotonic with respect to receipts emitted from the same kernel; Chio fails closed if the value is in the future relative to the kernel clock.",
            ge=0,
        ),
    ]
    request_id: Annotated[
        str,
        Field(
            description="Upstream request identifier returned by the provider for this call. Opaque to Chio; preserved verbatim so operators can correlate Chio receipts with provider-side logs.",
            min_length=1,
        ),
    ]
