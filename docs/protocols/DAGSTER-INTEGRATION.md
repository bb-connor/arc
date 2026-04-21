# Dagster Integration: Asset-Level Capability Governance

> **Status**: Tier 2 -- proposed April 2026
> **Priority**: Medium -- Dagster's asset-based model introduces an
> interesting mapping: asset materializations as capability-bounded tool
> invocations. Strong in ML/data pipelines where agent-driven data
> processing meets compliance requirements.

## 1. Why Dagster

Dagster is an asset-oriented data platform. Unlike task-based orchestrators
(Airflow, Prefect), Dagster organizes work around **software-defined
assets** -- data artifacts that are declared, materialized, and observed.

This maps to Chio differently than task-based systems:

- An **asset materialization** is a tool invocation (the tool produces or
  updates a data artifact)
- An **op** (operation) within a job is a capability-bounded execution step
- **Resources** (database connections, API clients) are capability targets
- **IO Managers** control where data lands -- a natural policy enforcement
  point for data sensitivity

### Chio Value in the Dagster Model

| Dagster Concept | Chio Mapping | Value |
|-----------------|-------------|-------|
| Asset materialization | Tool invocation + receipt | Attested proof that an asset was produced by an authorized agent |
| Op execution | Capability evaluation | Each op checked against scope before execution |
| Resource | Capability target | Database/API access governed by capability tokens |
| Sensor/Schedule | Trigger evaluation | Automated materializations require standing capability grants |
| Partition | Scope narrowing | Per-partition capability (e.g., only access region=EU data) |
| IO Manager | Data governance hook | Chio can enforce where sensitive data is written |

## 2. Architecture

```
Dagster Instance
+----------------------------------------------------------+
|                                                          |
|  Definitions                                             |
|  +---------------------------------------------------+  |
|  |  @asset(resource_defs={"chio": chio_resource})       |  |
|  |  def customer_embeddings(raw_data):                |  |
|  |      chio.evaluate("tools:embed", scope="ml:embed") |  |
|  |      return embed(raw_data)                        |  |
|  +---------------------------------------------------+  |
|                                                          |
|  Dagster Daemon / Worker                                 |
|  +---------------------------------------------------+  |
|  |  Asset Materialization                             |  |
|  |  op: customer_embeddings  -----> Chio Sidecar       |  |
|  |                                  (:9090)           |  |
|  |  Evaluate -> Guard -> Execute -> Receipt           |  |
|  +---------------------------------------------------+  |
|                                                          |
+----------------------------------------------------------+
```

## 3. Integration Model

### 3.1 Chio as a Dagster Resource

Dagster resources are dependency-injected into assets and ops. Chio fits
naturally as a resource:

```python
from dagster import resource, ConfigurableResource
from chio_sdk import ChioClient

class ChioResource(ConfigurableResource):
    """Chio protocol resource for capability-governed asset materializations."""

    sidecar_url: str = "http://127.0.0.1:9090"

    def evaluate(self, tool: str, scope: str, arguments: dict | None = None):
        client = ChioClient(base_url=self.sidecar_url)
        return client.evaluate(tool=tool, scope=scope, arguments=arguments or {})

    def record(self, verdict, result_hash: str | None = None):
        client = ChioClient(base_url=self.sidecar_url)
        return client.record(verdict=verdict, result_hash=result_hash)
```

### 3.2 Asset Decorator (`@chio_asset`)

```python
from dagster import asset, AssetExecutionContext, MaterializeResult, MetadataValue
from chio_dagster import chio_asset

@chio_asset(
    scope="ml:embed",
    guards=["pii-filter", "data-residency"],
    budget={"max_cost_usd": 10.00},
)
def customer_embeddings(context: AssetExecutionContext, raw_customers: pd.DataFrame) -> pd.DataFrame:
    """Materialize customer embeddings -- Chio-governed."""
    # If we reach here, Chio evaluated and approved the materialization
    embeddings = embedding_model.encode(raw_customers["text"].tolist())
    return pd.DataFrame({"id": raw_customers["id"], "embedding": embeddings})
```

Implementation:

```python
def chio_asset(scope: str, guards: list[str] | None = None, budget: dict | None = None, **asset_kwargs):
    """Wrap a Dagster asset with Chio capability enforcement."""

    def decorator(fn):
        @asset(**asset_kwargs)
        @functools.wraps(fn)
        def wrapper(context: AssetExecutionContext, **kwargs):
            chio: ChioResource = context.resources.chio

            verdict = chio.evaluate(
                tool=fn.__name__,
                scope=scope,
                arguments={"asset": fn.__name__, "partition": context.partition_key if context.has_partition_key else None},
            )

            if verdict.denied:
                context.log.error(f"Chio denied materialization of {fn.__name__}: {verdict.reason}")
                raise PermissionError(f"Chio denied: {verdict.reason}")

            result = fn(context, **kwargs)

            receipt = chio.record(verdict=verdict)
            context.log.info(f"Chio receipt: {receipt.receipt_id}")

            # Attach receipt as asset metadata
            context.add_output_metadata({
                "chio_receipt_id": MetadataValue.text(receipt.receipt_id),
                "chio_scope": MetadataValue.text(scope),
                "chio_verdict": MetadataValue.text("allow"),
            })

            return result

        return wrapper
    return decorator
```

### 3.3 Partition-Scoped Capabilities

Dagster partitions map to Chio scope narrowing. An asset partitioned by
region can have per-region capability checks:

```python
from dagster import DailyPartitionsDefinition, StaticPartitionsDefinition

region_partitions = StaticPartitionsDefinition(["us-east", "eu-west", "ap-south"])

@chio_asset(
    scope="data:process",
    partitions_def=region_partitions,
)
def regional_analytics(context: AssetExecutionContext, raw_events: pd.DataFrame) -> pd.DataFrame:
    # Chio evaluates with partition context:
    #   scope="data:process", arguments={"partition": "eu-west"}
    # Guard can enforce data residency: eu-west partition must run in EU
    return process_events(raw_events)
```

### 3.4 Op-Level Integration (Jobs)

For job/op-based Dagster code (non-asset):

```python
from dagster import op, job, In, Out
from chio_dagster import chio_op

@chio_op(scope="tools:query", guards=["rate-limit"])
def query_database(context, query: str) -> dict:
    return db.execute(query)

@chio_op(scope="tools:transform")
def transform_data(context, raw: dict) -> dict:
    return transform(raw)

@job(resource_defs={"chio": ChioResource()})
def analysis_job():
    raw = query_database()
    transform_data(raw)
```

### 3.5 Sensor and Schedule Governance

Dagster sensors and schedules trigger materializations automatically.
These need standing capability grants:

```python
from dagster import sensor, RunRequest
from chio_dagster import chio_sensor

@chio_sensor(
    scope="automation:trigger",
    # Standing grant: sensor can trigger materializations during business hours
    grant_schedule="cron:0 8-18 * * MON-FRI",
)
def new_data_sensor(context):
    if check_for_new_data():
        yield RunRequest(run_key="new-data", run_config={})
```

## 4. IO Manager Integration

Dagster IO Managers control data persistence. Chio can enforce data
governance at the IO Manager level:

```python
from dagster import IOManager, io_manager

class ChioGovernedIOManager(IOManager):
    """IO Manager that checks Chio data governance policy before writing."""

    def __init__(self, inner: IOManager, chio: ChioResource):
        self.inner = inner
        self.chio = chio

    def handle_output(self, context, obj):
        # Check if this output is allowed to be written to this destination
        verdict = self.chio.evaluate(
            tool="io:write",
            scope=f"data:write:{context.asset_key.to_user_string()}",
            arguments={
                "destination": type(self.inner).__name__,
                "asset": context.asset_key.to_user_string(),
                "partition": context.partition_key if context.has_partition_key else None,
            },
        )

        if verdict.denied:
            raise PermissionError(
                f"Chio data governance denied write of {context.asset_key}: {verdict.reason}"
            )

        self.inner.handle_output(context, obj)
        self.chio.record(verdict=verdict)

    def load_input(self, context):
        return self.inner.load_input(context)
```

## 5. Dagster UI Metadata

Chio receipts surface in the Dagster UI as asset metadata:

```
Asset: customer_embeddings
Materialization: 2026-04-15T14:30:00Z
  chio_receipt_id: "rcpt_abc123def456"
  chio_scope: "ml:embed"
  chio_verdict: "allow"
  chio_guards_evaluated: ["pii-filter", "data-residency"]
  chio_budget_remaining: "$7.50 / $10.00"
```

## 6. Package Structure

```
sdks/python/chio-dagster/
  pyproject.toml            # deps: chio-sdk-python, dagster>=1.7
  src/chio_dagster/
    __init__.py
    resource.py             # ChioResource (ConfigurableResource)
    decorators.py           # chio_asset, chio_op, chio_sensor
    io_manager.py           # ChioGovernedIOManager
    metadata.py             # Receipt-to-metadata formatting
  tests/
    test_chio_asset.py
    test_partition_scope.py
    test_io_manager.py
```

## 7. Open Questions

1. **Dagster+ (Cloud).** Dagster+ runs assets in managed infrastructure.
   The sidecar model needs the Chio kernel co-located with the worker. Does
   Dagster+ support sidecar containers in its agent model?

2. **Asset lineage and receipt chains.** Dagster tracks asset lineage
   (asset A depends on asset B). Should Chio receipt chains mirror this
   lineage, creating a cryptographic proof of the full data pipeline?

3. **Freshness policies.** Dagster freshness policies trigger
   re-materialization when data is stale. Should these triggers require
   their own capability evaluation, or inherit from the asset's grant?
