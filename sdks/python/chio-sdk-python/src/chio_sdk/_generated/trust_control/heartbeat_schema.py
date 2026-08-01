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


class ChioTrustControlLeaseHeartbeat(BaseModel):
    """
    One trust-control heartbeat used to refresh a held authority lease before it expires. The heartbeat names the lease being refreshed (`leaseId` plus `leaseEpoch`), the leader URL claiming continued ownership, and the unix-millisecond observation timestamp at which the heartbeat was issued. The contract is anchored by `spec/PROTOCOL.md` section 9 (the `/v1/internal/cluster/status` cluster lease lifecycle). Wire field names are camelCase to match the lease projection.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    leaderUrl: Annotated[
        str,
        Field(
            description="Normalized URL of the leader claiming continued ownership of the lease.",
            min_length=1,
        ),
    ]
    leaseEpoch: Annotated[
        int,
        Field(
            description="Lease epoch carried alongside `leaseId`. Trust-control fails closed if the heartbeat targets a stale epoch.",
            ge=0,
        ),
    ]
    leaseId: Annotated[
        str,
        Field(
            description="Lease identifier being refreshed. Must match the `leaseId` previously projected by the lease schema.",
            min_length=1,
        ),
    ]
    observedAt: Annotated[
        int,
        Field(
            description="Unix-millisecond timestamp at which the leader observed the cluster state that motivated this heartbeat.",
            ge=0,
        ),
    ]
    proposedExpiresAt: Annotated[
        int | None,
        Field(
            description="Optional unix-millisecond timestamp the leader proposes for the refreshed `leaseExpiresAt`. Trust-control may clamp this to the policy-bounded TTL.",
            ge=0,
        ),
    ] = None
