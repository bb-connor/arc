"""ARC Dagster integration.

Wraps Dagster's Python SDK (:mod:`dagster`) so every ``@arc_asset`` and
``@arc_op`` materialization flows through the ARC sidecar for
capability-scoped authorisation. Partition keys are forwarded into the
capability evaluation payload so operators can grant access to specific
partitions only (the canonical ``region=eu-west`` data-residency
pattern). Denied materializations raise :class:`PermissionError` (which
Dagster routes to a failed op / asset state); every allow verdict is
attached to the emitted :class:`dagster.AssetMaterialization` as
:class:`dagster.MetadataValue` entries so the Dagster UI renders
receipts on the asset catalog row.

Public surface:

* :func:`arc_asset` -- decorator that wraps a Python function as a
  Dagster :func:`dagster.asset` gated on an ARC capability check.
* :func:`arc_op` -- decorator that wraps a Python function as a
  Dagster :func:`dagster.op` with the same pre-execute gate.
* :class:`ArcIOManager` -- IO manager wrapper that evaluates a
  capability before delegating to an inner manager's
  :meth:`load_input` / :meth:`handle_output`.
* :class:`ArcDagsterError` / :class:`ArcDagsterConfigError` -- error
  types.

The decorators mirror the signatures of :func:`dagster.asset` and
:func:`dagster.op` so Dagster options (``partitions_def``, ``ins``,
``deps``, ``io_manager_key``, ``group_name``, ``retry_policy``, ...)
pass through verbatim.
"""

from arc_dagster.decorators import arc_asset, arc_op
from arc_dagster.errors import ArcDagsterConfigError, ArcDagsterError
from arc_dagster.io_manager import ArcIOManager
from arc_dagster.partitions import extract_partition_info

__all__ = [
    "ArcDagsterConfigError",
    "ArcDagsterError",
    "ArcIOManager",
    "arc_asset",
    "arc_op",
    "extract_partition_info",
]
