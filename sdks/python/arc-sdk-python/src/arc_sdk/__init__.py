"""ARC SDK for Python -- thin HTTP client to the ARC sidecar kernel."""

from arc_sdk.models import (
    ArcHttpRequest,
    ArcPassthrough,
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
    EvaluateResponse,
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
from arc_sdk.testing import (
    MockArcClient,
    MockVerdict,
    RecordedCall,
    allow_all,
    deny_all,
    with_policy,
)

__all__ = [
    # Client
    "ArcClient",
    # Testing
    "MockArcClient",
    "MockVerdict",
    "RecordedCall",
    "allow_all",
    "deny_all",
    "with_policy",
    # Models -- capabilities
    "CapabilityToken",
    "CapabilityTokenBody",
    "ArcScope",
    "ArcHttpRequest",
    "ArcPassthrough",
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
    "EvaluateResponse",
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
