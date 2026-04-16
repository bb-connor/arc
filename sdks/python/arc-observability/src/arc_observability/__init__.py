"""ARC observability bridges.

Push ARC receipts as enriched spans into agent observability platforms
(LangSmith, LangFuse) so every tool call trace includes the kernel's
guard evaluation result.

Public surface:

* :class:`LangSmithBridge` -- consume :class:`arc_sdk.models.ArcReceipt`
  objects and POST them as LangSmith runs.
* :class:`LangFuseBridge` -- same, but pushes to LangFuse as spans.
* :class:`ReceiptEnricher` -- build backend-neutral
  :class:`SpanPayload` objects; the bridges wrap this for their
  respective SDKs.
* :class:`ReceiptPoller` -- async tail loop over an ARC receipt source
  that forwards new receipts to the configured bridges.
* :class:`ArcObservabilityError` / :class:`ArcObservabilityConfigError` --
  error types.

Both backends are importable in isolation; the ``langsmith`` and
``langfuse`` SDKs are optional extras. Importing the top-level
package never requires either backend to be installed.
"""

from arc_observability.enricher import ReceiptEnricher, SpanPayload, TraceContext
from arc_observability.errors import ArcObservabilityConfigError, ArcObservabilityError
from arc_observability.langfuse_bridge import LangFuseBridge
from arc_observability.langsmith_bridge import LangSmithBridge
from arc_observability.poller import ErrorHandler, ReceiptPoller, ReceiptSource

__all__ = [
    "ArcObservabilityConfigError",
    "ArcObservabilityError",
    "ErrorHandler",
    "LangFuseBridge",
    "LangSmithBridge",
    "ReceiptEnricher",
    "ReceiptPoller",
    "ReceiptSource",
    "SpanPayload",
    "TraceContext",
]
