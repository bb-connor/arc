# arc-airflow

Apache Airflow integration for the [ARC protocol](../../../spec/PROTOCOL.md).
Wraps the two operator surfaces Airflow exposes (classic
`BaseOperator` subclasses and the TaskFlow API) so every task run is
capability-checked via the ARC sidecar kernel, denied tasks fail with
`AirflowException` whose `__cause__` is a `PermissionError` (per
roadmap 17.3), and receipt ids are pushed into XCom so downstream
tasks and the DAG listener can aggregate them into a workflow-level
trail.

## Install

```bash
uv pip install arc-airflow
# or
pip install arc-airflow
```

The package depends on `arc-sdk-python`, `apache-airflow>=2.8,<4`, and
`pydantic>=2.5`.

## Quickstart

### Wrap an existing operator

```python
from airflow import DAG
from airflow.providers.standard.operators.python import PythonOperator
from arc_sdk.models import ArcScope, Operation, ToolGrant
from arc_airflow import ArcOperator


SEARCH_SCOPE = ArcScope(
    grants=[
        ToolGrant(
            server_id="search-srv",
            tool_name="search_documents",
            operations=[Operation.INVOKE],
        ),
    ]
)


def search_inner(query: str) -> list[dict]:
    return external_search.run(query)


with DAG("agent_pipeline", schedule="@hourly") as dag:
    search = ArcOperator(
        inner_operator=PythonOperator(
            task_id="search_inner",
            python_callable=search_inner,
            op_kwargs={"query": "capability-based security"},
        ),
        scope=SEARCH_SCOPE,
        capability_id="cap-agent-pipeline",
        tool_server="search-srv",
    )
```

The wrapper exposes the standard Airflow scheduling kwargs (`retries`,
`retry_delay`, `trigger_rule`, ...) via `**operator_kwargs`; the inner
operator is constructed once and owned by the wrapper.

### TaskFlow API

```python
from airflow.decorators import dag
from arc_airflow import arc_task


@dag(schedule="@daily")
def agent_pipeline():

    @arc_task(
        scope=SEARCH_SCOPE,
        capability_id="cap-agent-pipeline",
        tool_server="search-srv",
    )
    def search(query: str) -> list[dict]:
        return search_engine.search(query)

    @arc_task(
        scope=ANALYSE_SCOPE,
        capability_id="cap-agent-pipeline",
        tool_server="search-srv",
    )
    def analyse(documents: list[dict]) -> dict:
        return analyser.run(documents)

    analyse(search("latest research"))


agent_pipeline()
```

### DAG listener

Register `ArcDAGListener` (via the bundled `AirflowPlugin`) to produce
a run-level receipt aggregation on `on_dag_run_success` /
`on_dag_run_failed`.

```python
# plugins/arc_airflow_plugin.py
from arc_airflow import airflow_plugin

# Airflow auto-discovers `AirflowPlugin` subclasses; the bundled
# plugin registers a process-wide ArcDAGListener that publishes the
# aggregated receipt ids under the `arc_receipt_ids` XCom key.
plugins = [airflow_plugin] if airflow_plugin is not None else []
```

## Behaviour

- Each `ArcOperator` / `@arc_task` invocation evaluates via the ARC
  sidecar before the inner task body runs. Allow verdicts proceed and
  push `arc_receipt_id` / `arc_scope` / `arc_capability_id` into XCom;
  deny verdicts raise `AirflowException` with a `PermissionError` as
  `__cause__`.
- The `PermissionError` carries a structured `arc_error`
  (`ArcAirflowError`) attribute with the guard, reason, receipt id,
  capability id, and decision envelope so structured-log consumers can
  inspect the full deny context.
- `ArcDAGListener.on_task_instance_success` /
  `on_task_instance_failed` pull the per-task receipt id from XCom and
  record it in the per-run aggregation. On `on_dag_run_success` /
  `on_dag_run_failed` the listener publishes the ordered list under
  `arc_receipt_ids` plus the terminal state under `arc_run_state`.
- Airflow's scheduling options (`retries`, `retry_delay`,
  `trigger_rule`, `queue`, ...) pass through verbatim to the
  `BaseOperator` constructor; the wrapper is a normal Airflow task.
- Sync and async TaskFlow bodies are both supported.

## Error types

- `ArcAirflowError` -- raised on deny; carries the structured verdict
  (guard, reason, receipt id, decision). Chained under `__cause__` on
  the `PermissionError` the wrapper raises.
- `ArcAirflowConfigError` -- raised at construction / decoration time
  for configuration mistakes (missing `capability_id`, missing
  `inner_operator`).

## Testing

The SDK ships a drop-in `MockArcClient` via `arc_sdk.testing`. Inject
it with `arc_client=` on either the operator or the decorator to
exercise DAGs offline:

```python
from arc_sdk.testing import allow_all, deny_all
from arc_airflow import ArcOperator, arc_task

# Offline allow
ArcOperator(
    inner_operator=PythonOperator(task_id="t", python_callable=lambda: 1),
    capability_id="cap-1",
    arc_client=allow_all(),
)

# Offline deny (raises AirflowException with PermissionError cause)
@arc_task(capability_id="cap-1", arc_client=deny_all())
def denied() -> None: ...
```

See `tests/test_operator.py`, `tests/test_task_decorator.py`, and
`tests/test_listener.py` in this repository for worked examples.
