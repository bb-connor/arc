"""ARC Airflow integration.

Wraps Apache Airflow's operator and TaskFlow surfaces so every task
run flows through the ARC sidecar for capability-scoped authorisation,
denied tasks fail with an :class:`airflow.exceptions.AirflowException`
whose ``__cause__`` is a :class:`PermissionError` (per the roadmap
17.3 acceptance criterion), and receipt ids are pushed into XCom on
the current task instance so downstream tasks and audit consumers can
build a DAG-level receipt timeline.

Public surface:

* :class:`ArcOperator` -- drop-in wrapper around any existing
  :class:`airflow.models.BaseOperator`. Calls the ARC sidecar before
  handing control to the inner operator's ``execute()`` and pushes the
  receipt id into XCom on allow.
* :func:`arc_task` -- TaskFlow API decorator that gates an ``@task``
  on an ARC capability evaluation.
* :class:`ArcDAGListener` -- Airflow listener (``@hookimpl``) that
  records per-task receipt ids and publishes a DAG-run aggregation at
  terminal transitions.
* :class:`ArcAirflowError` / :class:`ArcAirflowConfigError` -- error
  types.
"""

from arc_airflow.errors import ArcAirflowConfigError, ArcAirflowError
from arc_airflow.listener import (
    XCOM_RUN_RECEIPTS_KEY,
    XCOM_RUN_STATE_KEY,
    ArcDAGListener,
    airflow_plugin,
    get_listener,
)
from arc_airflow.operator import (
    XCOM_CAPABILITY_KEY,
    XCOM_RECEIPT_ID_KEY,
    XCOM_SCOPE_KEY,
    ArcOperator,
)
from arc_airflow.task_decorator import arc_task

__all__ = [
    "XCOM_CAPABILITY_KEY",
    "XCOM_RECEIPT_ID_KEY",
    "XCOM_RUN_RECEIPTS_KEY",
    "XCOM_RUN_STATE_KEY",
    "XCOM_SCOPE_KEY",
    "ArcAirflowConfigError",
    "ArcAirflowError",
    "ArcDAGListener",
    "ArcOperator",
    "airflow_plugin",
    "arc_task",
    "get_listener",
]
