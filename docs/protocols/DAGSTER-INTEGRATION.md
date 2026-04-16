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

This maps to ARC differently than task-based systems:

- An **asset materialization** is a tool invocation (the tool produces or
  updates a data artifact)
- An **op** (operation) within a job is a capability-bounded execution step
- **Resources** (database connections, API clients) are capability targets
- **IO Managers** control where data lands -- a natural policy enforcement
  point for data sensitivity

### ARC Value in the Dagster Model

| Dagster Concept | ARC Mapping | Value |
|-----------------|-------------|-------|
| Asset materialization | Tool invocation + receipt | Attested proof that an asset was produced by an authorized agent |
| Op execution | Capability evaluation | Each op checked against scope before execution |
| Resource | Capability target | Database/API access governed by capability tokens |
| Sensor/Schedule | Trigger evaluation | Automated materializations require standing capability grants |
| Partition | Scope narrowing | Per-partition capability (e.g., only access region=EU data) |
| IO Manager | Data governance hook | ARC can enforce where sensitive data is written |

## 2. Architecture

```
Dagster Instance
+----------------------------------------------------------+
|                                                          |
|  Definitions                                             |
|  +---------------------------------------------------+  |
|  |  @asset(resource_defs={"arc": arc_resource})       |  |
|  |  def customer_embeddings(raw_data):                |  |
|  |      arc.evaluate("tools:embed", scope="ml:embed") |  |
|  |      return embed(raw_data)                        |  |
|  +---------------------------------------------------+  |
|                                                          |
|  Dagster Daemon / Worker                                 |
|  +---------------------------------------------------+  |
|  |  Asset Materialization                             |  |
|  |  op: customer_embeddings  -----> ARC Sidecar       |  |
|  |                                  (:9090)           |  |
|  |  Evaluate -> Guard -> Execute -> Receipt           |  |
|  +---------------------------------------------------+  |
|                                                          |
+----------------------------------------------------------+
```

## 3. Integration Model

### 3.1 ARC as a Dagster Resource

Dagster resources are dependency-injected into assets and ops. ARC fits
naturally as a resource:

```python
from dagster import resource, ConfigurableResource
from arc_sdk import ArcClient

class ArcResource(ConfigurableResource):
    """ARC protocol resource for capability-governed asset materializations."""

    sidecar_url: str = "http://127.0.0.1:9090"

    def evaluate(self, tool: str, scope: str, arguments: dict | None = None):
        client = ArcClient(base_url=self.sidecar_url)
        return client.evaluate(tool=tool, scope=scope, arguments=arguments or {})

    def record(self, verdict, result_hash: str | None = None):
        client = ArcClient(base_url=self.sidecar_url)
        return client.record(verdict=verdict, result_hash=result_hash)
```

### 3.2 Asset Decorator (`@arc_asset`)

```python
from dagster import asset, AssetExecutionContext, MaterializeResult, MetadataValue
from arc_dagster import arc_asset

@arc_asset(
    scope="ml:embed",
    guards=["pii-filter", "data-residency"],
    budget={"max_cost_usd": 10.00},
)
def customer_embeddings(context: AssetExecutionContext, raw_customers: pd.DataFrame) -> pd.DataFrame:
    """Materialize customer embeddings -- ARC-governed."""
    # If we reach here, ARC evaluated and approved the materialization
    embeddings = embedding_model.encode(raw_customers["text"].tolist())
    return pd.DataFrame({"id": raw_customers["id"], "embedding": embeddings})
```

Implementation:

```python
def arc_asset(scope: str, guards: list[str] | None = None, budget: dict | None = None, **asset_kwargs):
    """Wrap a Dagster asset with ARC capability enforcement."""

    def decorator(fn):
        @asset(**asset_kwargs)
        @functools.wraps(fn)
        def wrapper(context: AssetExecutionContext, **kwargs):
            arc: ArcResource = context.resources.arc

            verdict = arc.evaluate(
                tool=fn.__name__,
                scope=scope,
                arguments={"asset": fn.__name__, "partition": context.partition_key if context.has_partition_key else None},
            )

            if verdict.denied:
                context.log.error(f"ARC denied materialization of {fn.__name__}: {verdict.reason}")
                raise PermissionError(f"ARC denied: {verdict.reason}")

            result = fn(context, **kwargs)

            receipt = arc.record(verdict=verdict)
            context.log.info(f"ARC receipt: {receipt.receipt_id}")

            # Attach receipt as asset metadata
            context.add_output_metadata({
                "arc_receipt_id": MetadataValue.text(receipt.receipt_id),
                "arc_scope": MetadataValue.text(scope),
                "arc_verdict": MetadataValue.text("allow"),
            })

            return result

        return wrapper
    return decorator
```

### 3.3 Partition-Scoped Capabilities

Dagster partitions map to ARC scope narrowing. An asset partitioned by
region can have per-region capability checks:

```python
from dagster import DailyPartitionsDefinition, StaticPartitionsDefinition

region_partitions = StaticPartitionsDefinition(["us-east", "eu-west", "ap-south"])

@arc_asset(
    scope="data:process",
    partitions_def=region_partitions,
)
def regional_analytics(context: AssetExecutionContext, raw_events: pd.DataFrame) -> pd.DataFrame:
    # ARC evaluates with partition context:
    #   scope="data:process", arguments={"partition": "eu-west"}
    # Guard can enforce data residency: eu-west partition must run in EU
    return process_events(raw_events)
```

### 3.4 Op-Level Integration (Jobs)

For job/op-based Dagster code (non-asset):

```python
from dagster import op, job, In, Out
from arc_dagster import arc_op

@arc_op(scope="tools:query", guards=["rate-limit"])
def query_database(context, query: str) -> dict:
    return db.execute(query)

@arc_op(scope="tools:transform")
def transform_data(context, raw: dict) -> dict:
    return transform(raw)

@job(resource_defs={"arc": ArcResource()})
def analysis_job():
    raw = query_database()
    transform_data(raw)
```

### 3.5 Sensor and Schedule Governance

Dagster sensors and schedules trigger materializations automatically.
These need standing capability grants:

```python
from dagster import sensor, RunRequest
from arc_dagster import arc_sensor

@arc_sensor(
    scope="automation:trigger",
    # Standing grant: sensor can trigger materializations during business hours
    grant_schedule="cron:0 8-18 * * MON-FRI",
)
def new_data_sensor(context):
    if check_for_new_data():
        yield RunRequest(run_key="new-data", run_config={})
```

## 4. IO Manager Integration

Dagster IO Managers control data persistence. ARC can enforce data
governance at the IO Manager level:

```python
from dagster import IOManager, io_manager

class ArcGovernedIOManager(IOManager):
    """IO Manager that checks ARC data governance policy before writing."""

    def __init__(self, inner: IOManager, arc: ArcResource):
        self.inner = inner
        self.arc = arc

    def handle_output(self, context, obj):
        # Check if this output is allowed to be written to this destination
        verdict = self.arc.evaluate(
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
                f"ARC data governance denied write of {context.asset_key}: {verdict.reason}"
            )

        self.inner.handle_output(context, obj)
        self.arc.record(verdict=verdict)

    def load_input(self, context):
        return self.inner.load_input(context)
```

## 5. Dagster UI Metadata

ARC receipts surface in the Dagster UI as asset metadata:

```
Asset: customer_embeddings
Materialization: 2026-04-15T14:30:00Z
  arc_receipt_id: "rcpt_abc123def456"
  arc_scope: "ml:embed"
  arc_verdict: "allow"
  arc_guards_evaluated: ["pii-filter", "data-residency"]
  arc_budget_remaining: "$7.50 / $10.00"
```

## 6. Package Structure

```
sdks/python/arc-dagster/
  pyproject.toml            # deps: arc-sdk-python, dagster>=1.7
  src/arc_dagster/
    __init__.py
    resource.py             # ArcResource (ConfigurableResource)
    decorators.py           # arc_asset, arc_op, arc_sensor
    io_manager.py           # ArcGovernedIOManager
    metadata.py             # Receipt-to-metadata formatting
  tests/
    test_arc_asset.py
    test_partition_scope.py
    test_io_manager.py
```

## 7. Open Questions

1. **Dagster+ (Cloud).** Dagster+ runs assets in managed infrastructure.
   The sidecar model needs the ARC kernel co-located with the worker. Does
   Dagster+ support sidecar containers in its agent model?

2. **Asset lineage and receipt chains.** Dagster tracks asset lineage
   (asset A depends on asset B). Should ARC receipt chains mirror this
   lineage, creating a cryptographic proof of the full data pipeline?

3. **Freshness policies.** Dagster freshness policies trigger
   re-materialization when data is stale. Should these triggers require
   their own capability evaluation, or inherit from the asset's grant?
