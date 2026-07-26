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

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class Reason(Enum):
    """
    Typed reason for releasing the lease. `leader_handoff` covers planned reassignment, `quorum_lost` covers detected loss of cluster quorum, `operator_stepdown` covers explicit operator action, and `term_advanced` covers a higher election term superseding the lease.
    """

    leader_handoff = "leader_handoff"
    quorum_lost = "quorum_lost"
    operator_stepdown = "operator_stepdown"
    term_advanced = "term_advanced"


class ChioTrustControlLeaseTermination(BaseModel):
    """
    One trust-control termination request that voluntarily releases a held authority lease before its TTL expires. Termination names the lease being released (`leaseId` plus `leaseEpoch`), the leader URL releasing it, and a typed `reason` so operators can distinguish leader handoff from quorum loss or operator-initiated stepdown. The contract is anchored by `spec/PROTOCOL.md` section 9, where loss of quorum or a leader change clears the lease expiry and bumps the election term. Wire field names are camelCase to match the sibling lease projection so the families stay consistent on the wire.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    leaderUrl: Annotated[
        str,
        Field(
            description="Normalized URL of the leader releasing the lease.",
            min_length=1,
        ),
    ]
    leaseEpoch: Annotated[
        int, Field(description="Lease epoch carried alongside `leaseId`.", ge=0)
    ]
    leaseId: Annotated[
        str,
        Field(
            description="Lease identifier being released. Must match the `leaseId` previously projected by the lease schema.",
            min_length=1,
        ),
    ]
    observedAt: Annotated[
        int,
        Field(
            description="Unix-millisecond timestamp at which the releasing leader observed the condition that motivated termination.",
            ge=0,
        ),
    ]
    reason: Annotated[
        Reason,
        Field(
            description="Typed reason for releasing the lease. `leader_handoff` covers planned reassignment, `quorum_lost` covers detected loss of cluster quorum, `operator_stepdown` covers explicit operator action, and `term_advanced` covers a higher election term superseding the lease."
        ),
    ]
    successorLeaderUrl: Annotated[
        str | None,
        Field(
            description="Optional normalized URL of the successor leader, when termination is part of a planned handoff.",
            min_length=1,
        ),
    ] = None
