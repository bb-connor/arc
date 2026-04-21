# Airflow Integration: Operator-Level Security Wrapper

> **Status**: Tier 2 -- proposed April 2026
> **Priority**: Medium-low -- massive installed base justifies presence, but
> the integration should be thin. Airflow is not agent-native; the value is
> "Chio works everywhere" positioning and brownfield adoption.

## 1. Why Airflow

Apache Airflow has the largest installed base of any workflow orchestrator.
Thousands of organizations run production data pipelines on Airflow. As
agents begin to participate in these pipelines -- triggering DAGs, running
operators, accessing data -- Chio governance needs to work in this
environment.

The integration strategy is deliberately thin: a custom Operator wrapper and
a DAG-level hook. Airflow's architecture (scheduler, worker, metadata DB)
is well-established and heavyweight. Chio should not try to deeply integrate
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
|  |  ChioOperator(                                      |  |
|  |    operator=PythonOperator(callable=search),       |  |
|  |    scope="tools:search",                           |  |
|  |  )                                                 |  |
|  |       |                                            |  |
|  |       v                                            |  |
|  |  Chio Sidecar (:9090)                               |  |
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

### 3.1 ChioOperator Wrapper

The primary integration point. Wraps any existing Airflow operator with
Chio capability enforcement:

```python
from airflow.models import BaseOperator
from chio_sdk import ChioClient


class ChioOperator(BaseOperator):
    """Wraps an inner operator with Chio capability evaluation.

    The inner operator only executes if the Chio kernel grants the
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
        arc = ChioClient(base_url=self.sidecar_url)

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
            self.log.error("Chio denied %s: %s", self.tool_name, verdict.reason)
            raise PermissionError(f"Chio denied: {verdict.reason}")

        # Execute the inner operator
        result = self.inner_operator.execute(context)

        # Record receipt and push to XCom
        receipt = arc.record_sync(verdict=verdict)
        context["ti"].xcom_push(key="chio_receipt_id", value=receipt.receipt_id)
        context["ti"].xcom_push(key="chio_scope", value=self.scope)

        return result
```

### 3.2 Usage in DAGs

```python
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.http.operators.http import SimpleHttpOperator
from chio_airflow import ChioOperator

with DAG("agent_pipeline", schedule="@hourly") as dag:

    # Wrap a PythonOperator
    search = ChioOperator(
        task_id="search",
        inner_operator=PythonOperator(
            task_id="search_inner",
            python_callable=search_function,
        ),
        scope="tools:search",
        guards=["rate-limit"],
    )

    # Wrap an HTTP operator
    api_call = ChioOperator(
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
from chio_airflow import chio_task

@dag(schedule="@daily")
def agent_pipeline():

    @chio_task(scope="tools:search", guards=["rate-limit"])
    def search(query: str) -> list[dict]:
        return search_engine.search(query)

    @chio_task(scope="tools:analyze")
    def analyze(documents: list[dict]) -> dict:
        return analyzer.run(documents)

    docs = search("latest research")
    analyze(docs)

agent_pipeline()
```

Implementation:

```python
from airflow.decorators import task as airflow_task

def chio_task(scope: str, guards: list[str] | None = None, budget: dict | None = None):
    """TaskFlow decorator with Chio governance."""

    def decorator(fn):
        @airflow_task(task_id=fn.__name__)
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            arc = ChioClient()

            verdict = arc.evaluate_sync(
                tool=fn.__name__,
                scope=scope,
                guards=guards,
                budget=budget,
            )

            if verdict.denied:
                raise PermissionError(f"Chio denied: {verdict.reason}")

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
from chio_sdk import ChioClient


class ChioDagListener:
    """Airflow listener that evaluates DAG-level Chio grants."""

    @hookimpl
    def on_dag_run_running(self, dag_run, msg):
        arc = ChioClient()
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
            raise PermissionError(f"Chio denied DAG {dag_run.dag_id}: {verdict.reason}")
```

### 3.5 Sensor Governance

Airflow sensors poll for conditions. Chio can govern what sensors are
allowed to poll and how frequently:

```python
from airflow.sensors.base import BaseSensorOperator
from chio_airflow import ChioOperator

# Wrap a sensor with Chio -- each poke is evaluated
check_data = ChioOperator(
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

Each ChioOperator pushes its receipt ID to XCom. A final task can aggregate
these into a workflow receipt:

```python
@chio_task(scope="receipts:aggregate")
def aggregate_receipts(**context):
    """Collect all Chio receipts from the DAG run into a workflow receipt."""
    arc = ChioClient()
    ti = context["ti"]

    # Pull receipt IDs from all upstream tasks
    receipt_ids = []
    for task_id in context["dag"].task_ids:
        rid = ti.xcom_pull(task_ids=task_id, key="chio_receipt_id")
        if rid:
            receipt_ids.append(rid)

    if receipt_ids:
        workflow_receipt = arc.finalize_workflow_sync(
            step_receipt_ids=receipt_ids,
            workflow_id=context["run_id"],
        )
        return workflow_receipt.receipt_id
```

## 5. Airflow Connection for Chio

```python
# Register as an Airflow connection type
from airflow.hooks.base import BaseHook

class ChioHook(BaseHook):
    conn_name_attr = "chio_conn_id"
    default_conn_name = "chio_default"
    conn_type = "arc"
    hook_name = "Chio Protocol"

    def __init__(self, chio_conn_id: str = default_conn_name):
        super().__init__()
        self.chio_conn_id = chio_conn_id
        self.connection = self.get_connection(chio_conn_id)

    def get_client(self) -> ChioClient:
        return ChioClient(base_url=self.connection.host)
```

## 6. Package Structure

```
sdks/python/chio-airflow/
  pyproject.toml            # deps: chio-sdk-python, apache-airflow>=2.8
  src/chio_airflow/
    __init__.py
    operators.py            # ChioOperator wrapper
    decorators.py           # chio_task (TaskFlow)
    hooks.py                # ChioHook (connection type)
    listeners.py            # ChioDagListener (DAG-level grants)
  tests/
    test_arc_operator.py
    test_taskflow.py
    test_dag_listener.py
```

## 7. Migration Path

For teams with existing Airflow DAGs, adoption is incremental:

1. **Deploy Chio sidecar** alongside Airflow workers
2. **Wrap high-risk operators** with `ChioOperator` (external API calls,
   database writes, ML model invocations)
3. **Add DAG listener** for DAG-level grant evaluation
4. **Migrate to `@chio_task`** in new TaskFlow DAGs
5. **Aggregate receipts** for audit trail

No changes to existing DAG structure required. Wrap-and-go.

## 8. Open Questions

1. **Managed Airflow.** MWAA (AWS), Cloud Composer (GCP), Astronomer --
   these manage the Airflow infrastructure. Can the Chio sidecar run as
   a sidecar container in these environments, or does it need to be a
   remote kernel?

2. **Dynamic task mapping.** Airflow 2.x dynamic task mapping
   (`expand()`) creates tasks at runtime. Should each mapped task instance
   get its own capability evaluation, or should the mapping as a whole
   get a single grant?

3. **Cross-DAG dependencies.** Airflow's `ExternalTaskSensor` creates
   cross-DAG dependencies. Should Chio capability grants span DAG
   boundaries?
