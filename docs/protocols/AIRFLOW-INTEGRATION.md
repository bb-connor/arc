# Airflow Integration: Operator-Level Security Wrapper

> **Status**: Tier 2 -- proposed April 2026
> **Priority**: Medium-low -- massive installed base justifies presence, but
> the integration should be thin. Airflow is not agent-native; the value is
> "ARC works everywhere" positioning and brownfield adoption.

## 1. Why Airflow

Apache Airflow has the largest installed base of any workflow orchestrator.
Thousands of organizations run production data pipelines on Airflow. As
agents begin to participate in these pipelines -- triggering DAGs, running
operators, accessing data -- ARC governance needs to work in this
environment.

The integration strategy is deliberately thin: a custom Operator wrapper and
a DAG-level hook. Airflow's architecture (scheduler, worker, metadata DB)
is well-established and heavyweight. ARC should not try to deeply integrate
with Airflow internals. Instead, wrap the execution boundary.

### Integration Scope

| In Scope | Out of Scope |
|----------|--------------|
| Operator execution wrapper | Scheduler integration |
| DAG-level capability grants | Airflow RBAC replacement |
| Receipt logging via XCom | Custom Airflow UI plugin |
| Sensor governance | Connection/variable governance |
| TaskFlow API decorator | Executor customization |

## 2. Architecture

```
Airflow Worker
+----------------------------------------------------------+
|                                                          |
|  DAG: agent_pipeline                                     |
|  +---------------------------------------------------+  |
|  |  ArcOperator(                                      |  |
|  |    operator=PythonOperator(callable=search),       |  |
|  |    scope="tools:search",                           |  |
|  |  )                                                 |  |
|  |       |                                            |  |
|  |       v                                            |  |
|  |  ARC Sidecar (:9090)                               |  |
|  |  evaluate -> guard -> allow/deny                   |  |
|  |       |                                            |  |
|  |       v (if allowed)                               |  |
|  |  PythonOperator.execute()                          |  |
|  |       |                                            |  |
|  |       v                                            |  |
|  |  Receipt -> XCom                                   |  |
|  +---------------------------------------------------+  |
|                                                          |
+----------------------------------------------------------+
```

## 3. Integration Model

### 3.1 ArcOperator Wrapper

The primary integration point. Wraps any existing Airflow operator with
ARC capability enforcement:

```python
from airflow.models import BaseOperator
from arc_sdk import ArcClient


class ArcOperator(BaseOperator):
    """Wraps an inner operator with ARC capability evaluation.

    The inner operator only executes if the ARC kernel grants the
    requested capability. A receipt is stored in XCom on success.
    """

    template_fields = ("scope", "tool_name")

    def __init__(
        self,
        *,
        inner_operator: BaseOperator,
        scope: str,
        tool_name: str | None = None,
        guards: list[str] | None = None,
        budget: dict | None = None,
        sidecar_url: str = "http://127.0.0.1:9090",
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.inner_operator = inner_operator
        self.scope = scope
        self.tool_name = tool_name or inner_operator.task_id
        self.guards = guards
        self.budget = budget
        self.sidecar_url = sidecar_url

    def execute(self, context):
        arc = ArcClient(base_url=self.sidecar_url)

        verdict = arc.evaluate_sync(
            tool=self.tool_name,
            scope=self.scope,
            arguments={
                "dag_id": context["dag"].dag_id,
                "run_id": context["run_id"],
                "task_id": self.task_id,
                "execution_date": str(context["execution_date"]),
            },
            guards=self.guards,
            budget=self.budget,
        )

        if verdict.denied:
            self.log.error("ARC denied %s: %s", self.tool_name, verdict.reason)
            raise PermissionError(f"ARC denied: {verdict.reason}")

        # Execute the inner operator
        result = self.inner_operator.execute(context)

        # Record receipt and push to XCom
        receipt = arc.record_sync(verdict=verdict)
        context["ti"].xcom_push(key="arc_receipt_id", value=receipt.receipt_id)
        context["ti"].xcom_push(key="arc_scope", value=self.scope)

        return result
```

### 3.2 Usage in DAGs

```python
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.http.operators.http import SimpleHttpOperator
from arc_airflow import ArcOperator

with DAG("agent_pipeline", schedule="@hourly") as dag:

    # Wrap a PythonOperator
    search = ArcOperator(
        task_id="search",
        inner_operator=PythonOperator(
            task_id="search_inner",
            python_callable=search_function,
        ),
        scope="tools:search",
        guards=["rate-limit"],
    )

    # Wrap an HTTP operator
    api_call = ArcOperator(
        task_id="api_call",
        inner_operator=SimpleHttpOperator(
            task_id="api_call_inner",
            endpoint="/api/process",
            method="POST",
        ),
        scope="tools:external-api",
        guards=["pii-filter"],
        budget={"max_calls": 50},
    )

    search >> api_call
```

### 3.3 TaskFlow API Decorator

For Airflow 2.x+ TaskFlow API:

```python
from airflow.decorators import dag, task
from arc_airflow import arc_task

@dag(schedule="@daily")
def agent_pipeline():

    @arc_task(scope="tools:search", guards=["rate-limit"])
    def search(query: str) -> list[dict]:
        return search_engine.search(query)

    @arc_task(scope="tools:analyze")
    def analyze(documents: list[dict]) -> dict:
        return analyzer.run(documents)

    docs = search("latest research")
    analyze(docs)

agent_pipeline()
```

Implementation:

```python
from airflow.decorators import task as airflow_task

def arc_task(scope: str, guards: list[str] | None = None, budget: dict | None = None):
    """TaskFlow decorator with ARC governance."""

    def decorator(fn):
        @airflow_task(task_id=fn.__name__)
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            arc = ArcClient()

            verdict = arc.evaluate_sync(
                tool=fn.__name__,
                scope=scope,
                guards=guards,
                budget=budget,
            )

            if verdict.denied:
                raise PermissionError(f"ARC denied: {verdict.reason}")

            result = fn(*args, **kwargs)

            receipt = arc.record_sync(verdict=verdict)
            # Push receipt to XCom via return metadata
            return result

        return wrapper
    return decorator
```

### 3.4 DAG-Level Hook

An Airflow listener (plugin) that evaluates a DAG-level grant before any
task in the DAG executes:

```python
from airflow.listeners import hookimpl
from arc_sdk import ArcClient


class ArcDagListener:
    """Airflow listener that evaluates DAG-level ARC grants."""

    @hookimpl
    def on_dag_run_running(self, dag_run, msg):
        arc = ArcClient()
        verdict = arc.evaluate_sync(
            tool=f"dag:{dag_run.dag_id}",
            scope="automation:dag-run",
            arguments={
                "dag_id": dag_run.dag_id,
                "run_id": dag_run.run_id,
                "run_type": dag_run.run_type,
                "external_trigger": dag_run.external_trigger,
            },
        )

        if verdict.denied:
            dag_run.set_state("failed")
            raise PermissionError(f"ARC denied DAG {dag_run.dag_id}: {verdict.reason}")
```

### 3.5 Sensor Governance

Airflow sensors poll for conditions. ARC can govern what sensors are
allowed to poll and how frequently:

```python
from airflow.sensors.base import BaseSensorOperator
from arc_airflow import ArcOperator

# Wrap a sensor with ARC -- each poke is evaluated
check_data = ArcOperator(
    task_id="check_data",
    inner_operator=S3KeySensor(
        task_id="check_data_inner",
        bucket_key="s3://data-lake/incoming/*.parquet",
        poke_interval=300,
    ),
    scope="sensors:s3:read",
)
```

## 4. Receipt Aggregation via XCom

Each ArcOperator pushes its receipt ID to XCom. A final task can aggregate
these into a workflow receipt:

```python
@arc_task(scope="receipts:aggregate")
def aggregate_receipts(**context):
    """Collect all ARC receipts from the DAG run into a workflow receipt."""
    arc = ArcClient()
    ti = context["ti"]

    # Pull receipt IDs from all upstream tasks
    receipt_ids = []
    for task_id in context["dag"].task_ids:
        rid = ti.xcom_pull(task_ids=task_id, key="arc_receipt_id")
        if rid:
            receipt_ids.append(rid)

    if receipt_ids:
        workflow_receipt = arc.finalize_workflow_sync(
            step_receipt_ids=receipt_ids,
            workflow_id=context["run_id"],
        )
        return workflow_receipt.receipt_id
```

## 5. Airflow Connection for ARC

```python
# Register as an Airflow connection type
from airflow.hooks.base import BaseHook

class ArcHook(BaseHook):
    conn_name_attr = "arc_conn_id"
    default_conn_name = "arc_default"
    conn_type = "arc"
    hook_name = "ARC Protocol"

    def __init__(self, arc_conn_id: str = default_conn_name):
        super().__init__()
        self.arc_conn_id = arc_conn_id
        self.connection = self.get_connection(arc_conn_id)

    def get_client(self) -> ArcClient:
        return ArcClient(base_url=self.connection.host)
```

## 6. Package Structure

```
sdks/python/arc-airflow/
  pyproject.toml            # deps: arc-sdk-python, apache-airflow>=2.8
  src/arc_airflow/
    __init__.py
    operators.py            # ArcOperator wrapper
    decorators.py           # arc_task (TaskFlow)
    hooks.py                # ArcHook (connection type)
    listeners.py            # ArcDagListener (DAG-level grants)
  tests/
    test_arc_operator.py
    test_taskflow.py
    test_dag_listener.py
```

## 7. Migration Path

For teams with existing Airflow DAGs, adoption is incremental:

1. **Deploy ARC sidecar** alongside Airflow workers
2. **Wrap high-risk operators** with `ArcOperator` (external API calls,
   database writes, ML model invocations)
3. **Add DAG listener** for DAG-level grant evaluation
4. **Migrate to `@arc_task`** in new TaskFlow DAGs
5. **Aggregate receipts** for audit trail

No changes to existing DAG structure required. Wrap-and-go.

## 8. Open Questions

1. **Managed Airflow.** MWAA (AWS), Cloud Composer (GCP), Astronomer --
   these manage the Airflow infrastructure. Can the ARC sidecar run as
   a sidecar container in these environments, or does it need to be a
   remote kernel?

2. **Dynamic task mapping.** Airflow 2.x dynamic task mapping
   (`expand()`) creates tasks at runtime. Should each mapped task instance
   get its own capability evaluation, or should the mapping as a whole
   get a single grant?

3. **Cross-DAG dependencies.** Airflow's `ExternalTaskSensor` creates
   cross-DAG dependencies. Should ARC capability grants span DAG
   boundaries?
