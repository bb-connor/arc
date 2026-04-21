"""Chio Temporal integration.

Wraps Temporal's Python SDK (:mod:`temporalio`) so every Activity
invocation flows through the Chio sidecar for capability-scoped
authorization and signed receipts, and every workflow emits an
aggregate :class:`WorkflowReceipt` on completion.

Public surface:

* :class:`ChioActivityInterceptor` -- worker-level
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
  Chio receipt store can ingest.
* :func:`build_chio_worker` -- convenience builder that wires the
  interceptor and grant plumbing onto a
  :class:`temporalio.worker.Worker`.
* :class:`ChioTemporalError` / :class:`ChioTemporalConfigError` -- error
  types.
"""

from chio_temporal.errors import ChioTemporalConfigError, ChioTemporalError
from chio_temporal.grants import WorkflowGrant
from chio_temporal.interceptor import (
    DENIED_ERROR_TYPE,
    ActivityGrantOverride,
    ChioActivityInterceptor,
)
from chio_temporal.receipt import (
    ENVELOPE_VERSION,
    WorkflowReceipt,
    WorkflowStepReceipt,
)
from chio_temporal.worker import build_chio_worker

__all__ = [
    "ActivityGrantOverride",
    "ChioActivityInterceptor",
    "ChioTemporalConfigError",
    "ChioTemporalError",
    "DENIED_ERROR_TYPE",
    "ENVELOPE_VERSION",
    "WorkflowGrant",
    "WorkflowReceipt",
    "WorkflowStepReceipt",
    "build_chio_worker",
]
