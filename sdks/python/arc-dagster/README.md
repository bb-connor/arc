# arc-dagster

Dagster integration for the [ARC protocol](../../../spec/PROTOCOL.md).
Wraps Dagster's `@asset` and `@op` decorators so every materialization
is capability-checked via the ARC sidecar kernel, denied materializations
raise `PermissionError` (which Dagster routes to a failed run state),
and every allow verdict is attached to the emitted
`AssetMaterialization` as `MetadataValue` entries so the Dagster UI
renders ARC receipts directly on the asset catalog.

## Install

```bash
uv pip install arc-dagster
# or
pip install arc-dagster
```

The package depends on `arc-sdk-python`, `dagster>=1.8,<2`, and
`pydantic>=2.5`.

## Quickstart

```python
from arc_sdk.models import ArcScope, Operation, ToolGrant
from dagster import (
    AssetExecutionContext,
    Definitions,
    StaticPartitionsDefinition,
)
from arc_dagster import arc_asset


REGION_PARTITIONS = StaticPartitionsDefinition(
    ["us-east", "eu-west", "ap-south"]
)

EMBED_SCOPE = ArcScope(
    grants=[
        ToolGrant(
            server_id="ml-srv",
            tool_name="customer_embeddings",
            operations=[Operation.INVOKE],
        )
    ]
)


@arc_asset(
    scope=EMBED_SCOPE,
    capability_id="cap-ml-embed",
    tool_server="ml-srv",
    partitions_def=REGION_PARTITIONS,
)
def customer_embeddings(
    context: AssetExecutionContext,
) -> list[dict]:
    # If we reach here, ARC evaluated and approved the materialization
    # for this partition (context.partition_key is included in the
    # evaluation payload).
    return embedding_model.encode_for(context.partition_key)


defs = Definitions(assets=[customer_embeddings])
```

## Behaviour

- Each `@arc_asset` materialization evaluates via the ARC sidecar
  before the compute function runs. Allow verdicts proceed; deny
  verdicts raise `PermissionError` and Dagster records a `FAILURE`
  run state.
- Partitioned assets include the partition key (and the full partition
  info) in the capability evaluation payload -- guards can grant
  access to specific partitions only (the canonical
  `region=eu-west` data-residency pattern).
- Allow receipts are attached to the emitted
  `AssetMaterialization` as `MetadataValue` entries:
  `arc_receipt_id`, `arc_verdict`, `arc_capability_id`,
  `arc_tool_server`, `arc_tool_name`, and -- when present --
  `arc_partition_key`.
- Deny verdicts attach `arc_verdict="deny"`, `arc_reason`, and
  `arc_guard` to the output metadata so the failure is traceable on
  the Dagster UI even though the run transitions to `FAILURE`.
- Dagster's `@asset` / `@op` options (`partitions_def`, `ins`,
  `deps`, `io_manager_key`, `group_name`, `retry_policy`, `metadata`,
  ...) pass through `@arc_asset` / `@arc_op` verbatim.
- Sync and async compute functions are both supported.

### `ArcIOManager`

Wraps an inner `IOManager` with an ARC capability check on every
`handle_output` / `load_input`. This is the natural enforcement
point for data governance: the IO manager knows the destination
(warehouse, S3 bucket, local FS) the asset will land in, and ARC
decides whether the capability permits writes there.

```python
from dagster import FilesystemIOManager
from arc_dagster import ArcIOManager

arc_governed_fs = ArcIOManager(
    FilesystemIOManager(base_dir="/var/dagster/storage"),
    capability_id="cap-data-governance",
    tool_server="arc_data",
).as_io_manager()

defs = Definitions(
    assets=[customer_embeddings],
    resources={"io_manager": arc_governed_fs},
)
```

Partition keys flow through to the IO manager evaluation payload
(`parameters["partition_key"]`) the same way they flow through to
the asset decorator's evaluation, so the same guards work on either
surface.

## Error types

- `ArcDagsterError` -- raised on deny. Carries the structured verdict
  (guard, reason, receipt id, partition key, decision). The decorator
  attaches it to `PermissionError.arc_error` so `except PermissionError`
  remains the canonical catch.
- `ArcDagsterConfigError` -- raised at materialization time for
  configuration mistakes (missing `capability_id`, wrapper with an
  inner manager that doesn't implement the `IOManager` interface).

## Testing

The SDK ships a drop-in `MockArcClient` via `arc_sdk.testing`. Inject
it with `arc_client=` on the decorator or IO manager to exercise your
pipeline offline:

```python
from arc_sdk.testing import allow_all, deny_all

@arc_asset(
    capability_id="cap-1",
    tool_server="srv",
    arc_client=allow_all(),
)
def my_asset(context: AssetExecutionContext) -> int: ...
```

See `tests/test_arc_asset.py` and `tests/test_io_manager.py` in this
repository for worked examples, including the partition-scoped deny
pattern.
