# chio-prefect

Prefect integration for the [Chio protocol](../../../spec/PROTOCOL.md).
Wraps Prefect's `@task` and `@flow` decorators so every task invocation
is capability-checked via the Chio sidecar kernel, denied tasks raise
`PermissionError` (which Prefect routes to a failed task-run state),
and every allow / deny verdict is emitted as a Prefect Event so the UI
renders Chio receipts directly on the flow-run timeline.

## Install

```bash
uv pip install chio-prefect
# or
pip install chio-prefect
```

The package depends on `chio-sdk-python`, `prefect>=3,<4`, and
`pydantic>=2.5`.

## Quickstart

```python
from chio_sdk.client import ChioClient
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_prefect import chio_flow, chio_task


PIPELINE_SCOPE = ChioScope(
    grants=[
        ToolGrant(
            server_id="search-srv",
            tool_name="search_documents",
            operations=[Operation.INVOKE],
        ),
        ToolGrant(
            server_id="search-srv",
            tool_name="analyze_results",
            operations=[Operation.INVOKE],
        ),
    ]
)


@chio_task(
    scope=ChioScope(
        grants=[
            ToolGrant(
                server_id="search-srv",
                tool_name="search_documents",
                operations=[Operation.INVOKE],
            )
        ]
    ),
    tool_server="search-srv",
)
def search_documents(query: str) -> list[dict]:
    return external_search.run(query)


@chio_task(tool_server="search-srv")
def analyze_results(documents: list[dict]) -> dict:
    return analyzer.run(documents)


@chio_flow(
    scope=PIPELINE_SCOPE,
    capability_id="cap-research-pipeline",
    tool_server="search-srv",
)
def research_pipeline(query: str) -> dict:
    docs = search_documents(query)
    return analyze_results(docs)


if __name__ == "__main__":
    print(research_pipeline("capability-based security"))
```

## Behaviour

- Each `@chio_task` call evaluates via the Chio sidecar before the task
  body runs. Allow verdicts proceed; deny verdicts raise
  `PermissionError` and Prefect records a `Failed` task-run state.
- The enclosing `@chio_flow` scope bounds every task's scope. A task
  whose scope is not a subset of the flow's scope fails with
  `ChioPrefectConfigError` before any sidecar call.
- Allow and deny verdicts are emitted as `arc.receipt.allow` and
  `arc.receipt.deny` Prefect Events with the receipt id, capability,
  tool server / name, guard, and reason, related to the task-run and
  flow-run resource ids so the Prefect UI timeline draws them on the
  right task.
- Prefect's `@task` and `@flow` options (`retries`, `retry_delay_seconds`,
  `tags`, `timeout_seconds`, `task_runner`, `name`, ...) pass through
  `@chio_task` / `@chio_flow` verbatim.
- Sync and async task bodies are both supported; the decorator preserves
  Prefect's sync / async contract.

### Prefect UI receipts

Receipts appear on the flow-run timeline as `arc.receipt.allow` and
`arc.receipt.deny` events. Click through to the event payload to see
the receipt id, capability id, and guard that produced the verdict.

> Screenshot placeholder: `docs/screenshots/prefect-ui-receipts.png`

### Prefect Automations

Because receipts are emitted as first-class Prefect Events, Automations
can trigger on repeated denials (for example to pause a deployment when
a rate-limit guard fires five times in five minutes):

```yaml
automations:
  - name: chio-denial-circuit-breaker
    trigger:
      type: event
      match:
        event: arc.receipt.deny
      threshold: 5
      within: 300
    actions:
      - type: pause-deployment
        deployment_id: "{{ deployment.id }}"
```

## Error types

- `ChioPrefectError` -- raised on deny. Carries the structured verdict
  (guard, reason, receipt id, full decision). The decorator surfaces
  this via `PermissionError.chio_error` so `except PermissionError`
  remains the canonical catch.
- `ChioPrefectConfigError` -- raised at decoration or call time for
  configuration mistakes (missing `capability_id` on a standalone task,
  task scope broader than its flow, etc.).

## Testing

The SDK ships a drop-in `MockChioClient` via `chio_sdk.testing`. Inject
it with `chio_client=` on either decorator to exercise your pipeline
offline:

```python
from chio_sdk.testing import allow_all, deny_all

@chio_task(chio_client=allow_all(), tool_server="t")
def my_task() -> int: ...
```

See `tests/test_task_decorator.py` and `tests/test_flow_attenuation.py`
in this repository for worked examples.
