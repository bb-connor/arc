# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 47c14e6bc7f276540f7ae14d78b3cfb7b2b67b0a023df6a65298a2fa4d2b38e5
#
# Manual edits will be overwritten by the next regeneration; the
# M01.P3.T5 spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class ChioProvenanceStamp(BaseModel):
    """
    One provenance stamp attached by a Chio provider adapter to every tool-call response that traverses the M07 tool-call fabric. The stamp names the upstream `provider` adapter that handled the call, the upstream `request_id` returned by that provider, the wire `api_version` of the upstream provider API, the `principal` Chio resolved as the calling subject, and the unix-second `received_at` timestamp at which the provider returned the response to Chio. The shape is owned by milestone M07 (provider-native adapters); milestone M01 ships only the wire form. Per `.planning/trajectory/01-spec-codegen-conformance.md` (Cross-doc references, M07 row), the canonical field set is `provider`, `request_id`, `api_version`, `principal`, `received_at`. NOTE: there is no live `ProvenanceStamp` Rust struct on this branch; M07's `chio-tool-call-fabric` crate consumes this schema as its trait surface and materializes the matching Rust type at that time. Field names are snake_case to match the convention used by the existing `RuntimeAttestationEvidence` provenance-adjacent shape in `crates/chio-core-types/src/capability.rs` (lines 484-507).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    provider: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the upstream provider adapter that handled the tool call (for example `openai`, `anthropic`, `google-vertex`). M07 owns the canonical adapter identifier registry.",
    )
    request_id: constr(min_length=1) = Field(
        ...,
        description="Upstream request identifier returned by the provider for this call. Opaque to Chio; preserved verbatim so operators can correlate Chio receipts with provider-side logs.",
    )
    api_version: constr(min_length=1) = Field(
        ...,
        description="Wire version of the upstream provider API that served the call. Free-form per provider (for example `2024-08-01-preview` for Azure OpenAI, `v1` for Anthropic). Frozen per stamp; bumps require a new stamp.",
    )
    principal: constr(min_length=1) = Field(
        ...,
        description="Calling subject Chio resolved at the kernel boundary, in the same canonical form used by capability tokens (subject public key or normalized workload identity). Bound into the provenance graph alongside the receipt principal.",
    )
    received_at: conint(ge=0) = Field(
        ...,
        description="Unix timestamp (seconds) at which Chio observed the provider response. Monotonic with respect to receipts emitted from the same kernel; M07 fails closed if the value is in the future relative to the kernel clock.",
    )
