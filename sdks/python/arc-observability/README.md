# arc-observability

LangSmith and LangFuse observability bridges for the
[ARC protocol](../../../spec/PROTOCOL.md). Push ARC receipts as
enriched spans into agent observability platforms so every tool-call
trace includes its guard-evaluation result.

## Install

The package ships with optional extras so installers can pick one or
both backends:

```bash
# LangSmith only
uv pip install 'arc-observability[langsmith]'

# LangFuse only
uv pip install 'arc-observability[langfuse]'

# Both
uv pip install 'arc-observability[all]'
```

The `arc-observability` package itself never imports either backend SDK
at module load time, so it is safe to install only the one you need.

## Quickstart: LangSmith

```python
from arc_observability import LangSmithBridge
from arc_sdk.client import ArcClient


bridge = LangSmithBridge(
    api_key="lsv2_...",
    project="arc-production",
)


async def publish_recent() -> None:
    async with ArcClient("http://127.0.0.1:9090") as arc:
        receipts = await fetch_new_receipts(arc)  # your receipt source
        for receipt in receipts:
            bridge.publish(receipt)
```

Each ARC receipt becomes one LangSmith `Run`:

* `name = receipt.tool_name`
* `run_type = "tool"`
* `inputs = receipt.action.parameters`
* `outputs = {decision, evidence, result?}`
* `tags = ["arc.verdict:allow", "arc.tool:search", "arc.guard:PathGuard", "arc.cost:42USD", ...]`
* `extra.metadata` carries capability id, receipt id, policy hash,
  kernel key, and any additional kernel metadata.

## Quickstart: LangFuse

```python
from arc_observability import LangFuseBridge


bridge = LangFuseBridge(
    public_key="pk-lf-...",
    secret_key="sk-lf-...",
    host="https://cloud.langfuse.com",
)

bridge.publish(receipt)
bridge.flush()
```

On a deny verdict, the span is published with `level="ERROR"` and
`status_message` set to the kernel's deny reason so LangFuse UIs
highlight it as a failed observation.

## Receipt poller

Tail a receipt source and forward to every configured bridge:

```python
import asyncio

from arc_observability import LangFuseBridge, LangSmithBridge, ReceiptPoller


async def fetch_new_receipts() -> list:
    # Replace with your kernel-specific receipt tail (SQLite cursor,
    # kernel receipt-stream API, Kafka consumer, etc.).
    return await arc.list_receipts(since=last_cursor)


async def main() -> None:
    poller = ReceiptPoller(
        source=fetch_new_receipts,
        bridges=[langsmith_bridge, langfuse_bridge],
        interval_seconds=2.0,
    )
    await poller.start()
    try:
        await asyncio.Event().wait()
    finally:
        await poller.stop()


asyncio.run(main())
```

The poller deduplicates on receipt id, never raises into the caller's
event loop, and applies exponential back-off on source failures.

## Enrichment

Both bridges share the backend-neutral `ReceiptEnricher`, which you can
override to stamp deployment tags on every span or redact parameters:

```python
from arc_observability import LangSmithBridge, ReceiptEnricher


enricher = ReceiptEnricher(
    default_tags=["env:prod", "service:arc-kernel"],
    include_parameters=False,       # hide raw params; hash still captured
    truncate_parameters=4096,       # cap large payloads
)

bridge = LangSmithBridge(
    api_key="lsv2_...",
    project="arc-production",
    enricher=enricher,
)
```

## Trace context propagation

If your agent propagates LangSmith / LangFuse trace ids into the ARC
kernel (via receipt `metadata.trace`), the bridges will attach
receipts to the existing trace instead of creating a standalone one:

```json
{
  "metadata": {
    "trace": {
      "langsmith_run_id": "run_abc",
      "langsmith_parent_run_id": "run_parent",
      "langfuse_trace_id": "trace_xyz",
      "langfuse_parent_observation_id": "obs_456"
    }
  }
}
```

## Error types

* `ArcObservabilityError` -- a bridge failed to publish a span. Carries
  `backend`, `receipt_id`, `tool_name`, and the underlying cause.
* `ArcObservabilityConfigError` -- the bridge configuration is invalid
  (missing credentials, missing project, unavailable SDK, etc.).

## Reference

See
[`docs/guards/11-SIEM-OBSERVABILITY-COMPLETION.md`](../../../docs/guards/11-SIEM-OBSERVABILITY-COMPLETION.md)
section 5 for the full bridge design (trace context propagation, span
schemas, polling model).

## Development

```bash
uv venv --python 3.11
uv pip install -e '.[dev,langsmith,langfuse]'
uv pip install -e ../arc-sdk-python

uv run pytest
uv run mypy src/
uv run ruff check src/ tests/
```
