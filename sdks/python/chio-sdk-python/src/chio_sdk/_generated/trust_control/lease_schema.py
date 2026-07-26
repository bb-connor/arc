# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class ChioTrustControlAuthorityLease(BaseModel):
    """
    One operator-visible authority lease projection emitted by the trust-control service over `/v1/internal/cluster/status` and the budget-write authority block. A lease names the leader URL that currently holds the trust-control authority, the cluster election term that minted it, the lease identifier and epoch that scope subsequent budget and revocation writes, and the unix-second expiry plus configured TTL that bound the lease's continued validity. Wire field names are camelCase. `leaseValid` is true only when the cluster has quorum and `leaseExpiresAt` is still in the future. NOTE: `leaseExpiresAt` and `termStartedAt` are unix seconds (`unix_timestamp_now() + leaseTtlMs / 1000`), even though `leaseTtlMs` itself is in milliseconds. The asymmetry mirrors the live runtime shape and is preserved on the wire so consumers do not have to re-scale by 1000.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    authorityId: Annotated[
        str,
        Field(
            description="Stable identifier for the authority that holds the lease. In the current bounded release this equals the leader URL.",
            min_length=1,
        ),
    ]
    leaderUrl: Annotated[
        str,
        Field(
            description="Normalized URL of the cluster node that currently holds the authority lease.",
            min_length=1,
        ),
    ]
    leaseEpoch: Annotated[
        int,
        Field(
            description="Lease epoch carried alongside `leaseId`. Currently equals `term`; kept distinct on the wire so future epoch bumps within a term remain expressible.",
            ge=0,
        ),
    ]
    leaseExpiresAt: Annotated[
        int,
        Field(
            description="Unix-second timestamp at which the lease expires if not renewed. Computed as `unix_timestamp_now() + leaseTtlMs / 1000`. The unit is seconds (not milliseconds) even though the configured TTL is expressed in milliseconds; downstream consumers MUST treat this field as a unix-second timestamp.",
            ge=0,
        ),
    ]
    leaseId: Annotated[
        str,
        Field(
            description="Composite lease identifier in the form `{leaderUrl}#term-{leaseEpoch}`. Authoritative for downstream writes.",
            min_length=1,
        ),
    ]
    leaseTtlMs: Annotated[
        int,
        Field(
            description="Configured lease time-to-live in milliseconds. Bounded between 500ms and 5000ms. NOTE: this field is the only millisecond-denominated quantity in the lease projection; `termStartedAt` and `leaseExpiresAt` are unix seconds.",
            ge=0,
        ),
    ]
    leaseValid: Annotated[
        bool,
        Field(
            description="True only when the cluster currently has quorum and `leaseExpiresAt` has not yet passed. Trust-control fails closed and rejects authority-bearing writes when this is false."
        ),
    ]
    term: Annotated[
        int,
        Field(
            description="Cluster election term that minted this lease. Monotonically non-decreasing.",
            ge=0,
        ),
    ]
    termStartedAt: Annotated[
        int | None,
        Field(
            description="Optional unix-second timestamp at which the current term began on this leader. Omitted when unknown (no quorum or no leader).",
            ge=0,
        ),
    ] = None
