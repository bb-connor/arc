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

from pydantic import BaseModel, ConfigDict, Field, constr


class ChioCapabilityRevocationEntry(BaseModel):
    """
    A single revocation entry recording that a previously issued capability token (identified by its `id`) is no longer valid as of `revoked_at`. Mirrors `RevocationRecord` in `crates/kernel/chio-kernel/src/revocation_store.rs` (the kernel's persisted revocation row), and is the wire-level companion to the `capability_revoked` kernel notification under `chio-wire/v1/kernel/capability_revoked.schema.json`. Operators read these entries from `/admin/revocations` (hosted edge) and from the trust-control revocation list.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: constr(min_length=1) = Field(
        ...,
        description="The `id` field of the revoked CapabilityToken. Used to match revocations against presented tokens.",
    )
    revoked_at: int = Field(
        ...,
        description="Unix timestamp (seconds) at which the revocation took effect. Stored as a signed integer in the kernel store; negative values are not produced by the issuer but are not rejected here in order to match the Rust `i64` shape.",
    )
