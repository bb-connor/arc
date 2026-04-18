"""ARC Temporal integration.

Wraps Temporal's Python SDK (:mod:`temporalio`) so every Activity
invocation flows through the ARC sidecar for capability-scoped
authorization and signed receipts, and every workflow emits an
aggregate :class:`WorkflowReceipt` on completion.

Public surface:

* :class:`ArcActivityInterceptor` -- worker-level
  :class:`temporalio.worker.Interceptor` that gates Activity
  execution. Denied activities raise
  :class:`temporalio.exceptions.ApplicationError` with
  ``non_retryable=True``.
* :class:`WorkflowGrant` -- capability token pinned to a Temporal
  ``workflow_id``. Activities inherit the grant by default;
  per-activity attenuation is supported via
  :meth:`WorkflowGrant.attenuate_for_activity`.
* :class:`WorkflowReceipt` -- aggregate of all per-activity receipts
  captured during a workflow run, serialised to a JSON envelope the
  ARC receipt store can ingest.
* :func:`build_arc_worker` -- convenience builder that wires the
  interceptor and grant plumbing onto a
  :class:`temporalio.worker.Worker`.
* :class:`ArcTemporalError` / :class:`ArcTemporalConfigError` -- error
  types.
"""

from arc_temporal.errors import ArcTemporalConfigError, ArcTemporalError
from arc_temporal.grants import WorkflowGrant
from arc_temporal.interceptor import (
    DENIED_ERROR_TYPE,
    ActivityGrantOverride,
    ArcActivityInterceptor,
)
from arc_temporal.receipt import (
    ENVELOPE_VERSION,
    WorkflowReceipt,
    WorkflowStepReceipt,
)
from arc_temporal.worker import build_arc_worker

__all__ = [
    "ActivityGrantOverride",
    "ArcActivityInterceptor",
    "ArcTemporalConfigError",
    "ArcTemporalError",
    "DENIED_ERROR_TYPE",
    "ENVELOPE_VERSION",
    "WorkflowGrant",
    "WorkflowReceipt",
    "WorkflowStepReceipt",
    "build_arc_worker",
]
