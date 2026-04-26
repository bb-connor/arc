# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: addbe60437bb0258103fb68da7ee1ee5c1d4fade2ca6aab98f2d5ddc89f0b7e1
#
# Manual edits will be overwritten by the next regeneration; the
# M01.P3.T5 spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class ChioTrustControlAuthorityLease(BaseModel):
    """
    One operator-visible authority lease projection emitted by the trust-control service over `/v1/internal/cluster/status` and the budget-write authority block. A lease names the leader URL that currently holds the trust-control authority, the cluster election term that minted it, the lease identifier and epoch that scope subsequent budget and revocation writes, and the unix-millisecond expiry plus configured TTL that bound the lease's continued validity. Mirrors the `ClusterAuthorityLeaseView` serde shape in `crates/chio-cli/src/trust_control/service_types.rs` (lines 1837-1848). The view uses `serde(rename_all = camelCase)` so wire field names are camelCase. The shape is constructed in `crates/chio-cli/src/trust_control/cluster_and_reports.rs` (`cluster_authority_lease_view_locked`, lines 841-862) from the live cluster consensus view; `leaseValid` is true only when the cluster has quorum and `leaseExpiresAt` is still in the future.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    authorityId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier for the authority that holds the lease. In the current bounded release this equals the leader URL.",
    )
    leaderUrl: constr(min_length=1) = Field(
        ...,
        description="Normalized URL of the cluster node that currently holds the authority lease.",
    )
    term: conint(ge=0) = Field(
        ...,
        description="Cluster election term that minted this lease. Monotonically non-decreasing.",
    )
    leaseId: constr(min_length=1) = Field(
        ...,
        description="Composite lease identifier in the form `{leaderUrl}#term-{leaseEpoch}`. Authoritative for downstream writes.",
    )
    leaseEpoch: conint(ge=0) = Field(
        ...,
        description="Lease epoch carried alongside `leaseId`. Currently equals `term`; kept distinct on the wire so future epoch bumps within a term remain expressible.",
    )
    termStartedAt: conint(ge=0) | None = Field(
        None,
        description="Optional unix-millisecond timestamp at which the current term began on this leader. Omitted via `serde(skip_serializing_if = Option::is_none)` when unknown.",
    )
    leaseExpiresAt: conint(ge=0) = Field(
        ...,
        description="Unix-millisecond timestamp at which the lease expires if not renewed.",
    )
    leaseTtlMs: conint(ge=0) = Field(
        ...,
        description="Configured lease time-to-live in milliseconds. Bounded between 500ms and 5000ms by `authority_lease_ttl` (cluster_and_reports.rs lines 832-839).",
    )
    leaseValid: bool = Field(
        ...,
        description="True only when the cluster currently has quorum and `leaseExpiresAt` has not yet passed. Trust-control fails closed and rejects authority-bearing writes when this is false.",
    )
