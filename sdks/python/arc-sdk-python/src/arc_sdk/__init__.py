"""ARC SDK for Python -- thin HTTP client to the ARC sidecar kernel."""

from arc_sdk.models import (
    ArcReceipt,
    ArcScope,
    Attenuation,
    AuthMethod,
    CallerIdentity,
    CapabilityToken,
    CapabilityTokenBody,
    Constraint,
    Decision,
    DelegationLink,
    GuardEvidence,
    HttpReceipt,
    MonetaryAmount,
    Operation,
    PromptGrant,
    ResourceGrant,
    ToolCallAction,
    ToolGrant,
    Verdict,
)
from arc_sdk.client import ArcClient
from arc_sdk.errors import (
    ArcError,
    ArcConnectionError,
    ArcDeniedError,
    ArcTimeoutError,
    ArcValidationError,
)

__all__ = [
    # Client
    "ArcClient",
    # Models -- capabilities
    "CapabilityToken",
    "CapabilityTokenBody",
    "ArcScope",
    "ToolGrant",
    "ResourceGrant",
    "PromptGrant",
    "Operation",
    "Constraint",
    "MonetaryAmount",
    "DelegationLink",
    "Attenuation",
    # Models -- receipts
    "ArcReceipt",
    "HttpReceipt",
    "Decision",
    "Verdict",
    "ToolCallAction",
    "GuardEvidence",
    # Models -- identity
    "CallerIdentity",
    "AuthMethod",
    # Errors
    "ArcError",
    "ArcConnectionError",
    "ArcDeniedError",
    "ArcTimeoutError",
    "ArcValidationError",
]
