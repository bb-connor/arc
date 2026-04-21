"""Tests for :class:`chio_airflow.ChioDAGListener`.

The listener is a plain Python class whose ``@hookimpl``-decorated
methods are callable directly. We drive it with synthetic task
instances that mimic the ``xcom_push`` / ``xcom_pull`` surface so we
can assert the receipt aggregation behaviour without a live scheduler.
"""

from __future__ import annotations

from typing import Any

from chio_airflow import (
    XCOM_RECEIPT_ID_KEY,
    XCOM_RUN_RECEIPTS_KEY,
    XCOM_RUN_STATE_KEY,
    ChioDAGListener,
)


class _FakeTI:
    """Stand-in for a TaskInstance with an in-memory XCom map."""

    def __init__(
        self,
        *,
        task_id: str,
        dag_id: str,
        run_id: str,
        xcom_seed: dict[str, Any] | None = None,
    ) -> None:
        self.task_id = task_id
        self.dag_id = dag_id
        self.run_id = run_id
        # The ``xcom_seed`` lets tests pre-populate the per-task XCom
        # the way the ChioOperator / chio_task decorator would.
        self._xcom: dict[tuple[str, str], Any] = {}
        if xcom_seed:
            for key, value in xcom_seed.items():
                self._xcom[(task_id, key)] = value
        self.pushed: list[tuple[str, Any]] = []

    def xcom_push(self, key: str, value: Any) -> None:
        self._xcom[(self.task_id, key)] = value
        self.pushed.append((key, value))

    def xcom_pull(
        self,
        *,
        task_ids: str,
        key: str = "return_value",
    ) -> Any:
        return self._xcom.get((task_ids, key))


class _FakeDagRun:
    def __init__(self, *, dag_id: str, run_id: str, tis: list[_FakeTI]) -> None:
        self.dag_id = dag_id
        self.run_id = run_id
        self._tis = list(tis)

    def get_task_instances(self) -> list[_FakeTI]:
        return list(self._tis)


# ---------------------------------------------------------------------------
# (a) Receipt id pushed into the per-run aggregation on task_success
# ---------------------------------------------------------------------------


class TestReceiptAggregation:
    def test_success_records_receipt_id_for_run(self) -> None:
        listener = ChioDAGListener()

        ti = _FakeTI(
            task_id="search",
            dag_id="pipeline",
            run_id="run-1",
            xcom_seed={XCOM_RECEIPT_ID_KEY: "receipt-abc"},
        )
        listener.on_task_instance_success(previous_state=None, task_instance=ti)

        receipts = listener.receipts_for("pipeline", "run-1")
        assert receipts == ["receipt-abc"]

    def test_failure_also_records_receipt_id(self) -> None:
        """Deny verdicts fail the task but still emit a receipt."""
        listener = ChioDAGListener()

        ti = _FakeTI(
            task_id="write",
            dag_id="pipeline",
            run_id="run-1",
            xcom_seed={XCOM_RECEIPT_ID_KEY: "receipt-deny"},
        )
        listener.on_task_instance_failed(
            previous_state=None, task_instance=ti, error=RuntimeError("boom")
        )
        assert listener.receipts_for("pipeline", "run-1") == ["receipt-deny"]

    def test_ungoverned_task_does_not_record(self) -> None:
        listener = ChioDAGListener()
        ti = _FakeTI(task_id="noop", dag_id="pipeline", run_id="run-1")
        listener.on_task_instance_success(previous_state=None, task_instance=ti)
        assert listener.receipts_for("pipeline", "run-1") == []

    def test_runs_are_isolated(self) -> None:
        """Receipts captured for one run do not leak into another."""
        listener = ChioDAGListener()
        ti_a = _FakeTI(
            task_id="t",
            dag_id="pipeline",
            run_id="run-a",
            xcom_seed={XCOM_RECEIPT_ID_KEY: "receipt-a"},
        )
        ti_b = _FakeTI(
            task_id="t",
            dag_id="pipeline",
            run_id="run-b",
            xcom_seed={XCOM_RECEIPT_ID_KEY: "receipt-b"},
        )
        listener.on_task_instance_success(previous_state=None, task_instance=ti_a)
        listener.on_task_instance_success(previous_state=None, task_instance=ti_b)

        assert listener.receipts_for("pipeline", "run-a") == ["receipt-a"]
        assert listener.receipts_for("pipeline", "run-b") == ["receipt-b"]

    def test_duplicate_pushes_are_deduped(self) -> None:
        """Listener is idempotent across repeated hook calls for one TI."""
        listener = ChioDAGListener()
        ti = _FakeTI(
            task_id="t",
            dag_id="pipeline",
            run_id="run-1",
            xcom_seed={XCOM_RECEIPT_ID_KEY: "receipt-one"},
        )
        listener.on_task_instance_success(previous_state=None, task_instance=ti)
        listener.on_task_instance_success(previous_state=None, task_instance=ti)
        assert listener.receipts_for("pipeline", "run-1") == ["receipt-one"]


# ---------------------------------------------------------------------------
# (b) DAG-run finalisation pushes the aggregated list to XCom
# ---------------------------------------------------------------------------


class TestDagRunFinalisation:
    def test_success_pushes_aggregation_to_last_ti(self) -> None:
        listener = ChioDAGListener()

        ti_search = _FakeTI(
            task_id="search",
            dag_id="pipeline",
            run_id="run-1",
            xcom_seed={XCOM_RECEIPT_ID_KEY: "receipt-search"},
        )
        ti_analyse = _FakeTI(
            task_id="analyse",
            dag_id="pipeline",
            run_id="run-1",
            xcom_seed={XCOM_RECEIPT_ID_KEY: "receipt-analyse"},
        )
        listener.on_task_instance_success(previous_state=None, task_instance=ti_search)
        listener.on_task_instance_success(previous_state=None, task_instance=ti_analyse)

        dag_run = _FakeDagRun(
            dag_id="pipeline",
            run_id="run-1",
            tis=[ti_search, ti_analyse],
        )
        listener.on_dag_run_success(dag_run=dag_run)

        # The aggregation lands on the last TI in the run (no aggregator
        # task present to target).
        pushed = dict(ti_analyse.pushed)
        assert pushed[XCOM_RUN_RECEIPTS_KEY] == ["receipt-search", "receipt-analyse"]
        assert pushed[XCOM_RUN_STATE_KEY] == "success"

        # Run entry drained post-finalisation.
        assert listener.receipts_for("pipeline", "run-1") == []

    def test_aggregation_targets_aggregator_task_when_present(self) -> None:
        listener = ChioDAGListener()
        ti_search = _FakeTI(
            task_id="search",
            dag_id="pipeline",
            run_id="run-1",
            xcom_seed={XCOM_RECEIPT_ID_KEY: "receipt-search"},
        )
        ti_aggregate = _FakeTI(
            task_id="aggregate_receipts",
            dag_id="pipeline",
            run_id="run-1",
        )
        listener.on_task_instance_success(previous_state=None, task_instance=ti_search)

        dag_run = _FakeDagRun(
            dag_id="pipeline",
            run_id="run-1",
            tis=[ti_search, ti_aggregate],
        )
        listener.on_dag_run_success(dag_run=dag_run)

        aggregated = dict(ti_aggregate.pushed)
        assert aggregated[XCOM_RUN_RECEIPTS_KEY] == ["receipt-search"]
        assert aggregated[XCOM_RUN_STATE_KEY] == "success"

    def test_failure_state_is_recorded(self) -> None:
        listener = ChioDAGListener()
        ti = _FakeTI(
            task_id="denied",
            dag_id="pipeline",
            run_id="run-1",
            xcom_seed={XCOM_RECEIPT_ID_KEY: "receipt-denied"},
        )
        listener.on_task_instance_failed(previous_state=None, task_instance=ti)

        dag_run = _FakeDagRun(dag_id="pipeline", run_id="run-1", tis=[ti])
        listener.on_dag_run_failed(dag_run=dag_run)

        pushed = dict(ti.pushed)
        assert pushed[XCOM_RUN_RECEIPTS_KEY] == ["receipt-denied"]
        assert pushed[XCOM_RUN_STATE_KEY] == "failed"
