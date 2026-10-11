"""Pydantic models for the HITL approval HTTP surface.

These mirror the wire shapes served by chio-api-protect under
``/approvals/*``. Two families of routes exist:

1. Inspection: ``GET /approvals/pending``, ``GET /approvals/{id}``.
2. Resolution: ``POST /approvals/{id}/respond`` (signed
   ``GovernedApprovalToken``), ``POST /approvals/batch/respond``,
3. Submission: ``POST /approvals/submit`` takes a full signed capability
   and exact arguments. The service builds the bound intent.

Decision tokens are supplied as dictionaries signed by an explicitly
configured approver. The control bearer and receipt signer cannot approve.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ApprovalVerdict(str, Enum):
    """Approver decision. Wire form is ``"approved"`` or ``"denied"``.

    The Hermes slash command exposes the friendlier verbs ``approve`` /
    ``deny`` and maps them through :meth:`from_action`.
    """

    APPROVED = "approved"
    DENIED = "denied"

    @classmethod
    def from_action(cls, action: str) -> ApprovalVerdict:
        """Coerce ``approve``/``deny`` shorthand into the wire enum."""

        normalised = action.strip().lower()
        if normalised in {"approve", "approved", "allow"}:
            return cls.APPROVED
        if normalised in {"deny", "denied", "reject", "rejected"}:
            return cls.DENIED
        raise ValueError(
            f"unknown approval action {action!r}; expected approve or deny"
        )


class PendingApproval(BaseModel):
    """One row from ``GET /approvals/pending``.

    Mirrors :class:`chio_kernel::ApprovalRequest` from the Rust crate.
    Unknown fields are tolerated so future additions to the Rust shape
    do not break older SDK consumers.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    approval_id: str
    policy_id: str
    subject_id: str
    capability_id: str
    tool_server: str
    tool_name: str
    action: str
    parameter_hash: str
    expires_at: int
    created_at: int
    summary: str
    triggered_by: list[str] = Field(default_factory=list)


class ResolvedApproval(BaseModel):
    """Resolved-approval audit row returned by ``GET /approvals/{id}``."""

    model_config = ConfigDict(extra="allow")

    approval_id: str
    outcome: ApprovalVerdict
    resolved_at: int
    approver_hex: str
    token_id: str


class Approval(BaseModel):
    """Response shape for ``GET /approvals/{id}``.

    Either ``pending`` or ``resolution`` is populated. Current resolved rows
    retain their original request and signed token inside ``resolution``;
    older audit-only rows can omit those artifacts.
    """

    model_config = ConfigDict(extra="allow")

    pending: PendingApproval | None = None
    resolution: ResolvedApproval | None = None


class PendingApprovalList(BaseModel):
    """Response shape for ``GET /approvals/pending``."""

    model_config = ConfigDict(extra="allow")

    approvals: list[PendingApproval] = Field(default_factory=list)
    count: int = 0


class ApprovalResponse(BaseModel):
    """Response shape for ``POST /approvals/{id}/respond``.

    The signed-token ``/respond`` route returns the same shape via
    :class:`chio_http_core::RespondResponse`.
    """

    model_config = ConfigDict(extra="allow")

    approval_id: str
    outcome: ApprovalVerdict
    resolved_at: int


class SubmitApprovalResult(BaseModel):
    """Response shape for ``POST /approvals/submit``.

    ``trusted_approvers`` is the list of public keys (hex) authorized
    to resolve this request. Signatures must come from the explicitly
    configured approver roster. Receipt signers gain no approval authority.
    """

    model_config = ConfigDict(extra="allow")

    approval_id: str
    expires_at: int
    created_at: int
    trusted_approvers: list[str] = Field(default_factory=list)


__all__ = [
    "Approval",
    "ApprovalResponse",
    "ApprovalVerdict",
    "PendingApproval",
    "PendingApprovalList",
    "ResolvedApproval",
    "SubmitApprovalResult",
]
