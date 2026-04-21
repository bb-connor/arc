"""Chio SDK for Python -- thin HTTP client to the Chio sidecar kernel."""

from chio_sdk.models import (
    ChioHttpRequest,
    ChioPassthrough,
    ChioReceipt,
    ChioScope,
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
from chio_sdk.client import ChioClient
from chio_sdk.errors import (
    ChioError,
    ChioConnectionError,
    ChioDeniedError,
    ChioTimeoutError,
    ChioValidationError,
)
from chio_sdk.testing import (
    MockChioClient,
    MockVerdict,
    RecordedCall,
    allow_all,
    deny_all,
    with_policy,
)

__all__ = [
    # Client
    "ChioClient",
    # Testing
    "MockChioClient",
    "MockVerdict",
    "RecordedCall",
    "allow_all",
    "deny_all",
    "with_policy",
    # Models -- capabilities
    "CapabilityToken",
    "CapabilityTokenBody",
    "ChioScope",
    "ChioHttpRequest",
    "ChioPassthrough",
    "ToolGrant",
    "ResourceGrant",
    "PromptGrant",
    "Operation",
    "Constraint",
    "MonetaryAmount",
    "DelegationLink",
    "Attenuation",
    # Models -- receipts
    "ChioReceipt",
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
    "ChioError",
    "ChioConnectionError",
    "ChioDeniedError",
    "ChioTimeoutError",
    "ChioValidationError",
]
