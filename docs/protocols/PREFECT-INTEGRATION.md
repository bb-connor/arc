# Prefect Integration: ML Pipeline Task Security

> **Status**: Tier 2 -- proposed April 2026
> **Priority**: Medium -- Prefect's `@task` decorator model maps cleanly to
> Chio's `@chio_requires` pattern. Growing adoption in ML/AI pipelines where
> agent-driven data processing needs tool-level governance.

## 1. Why Prefect

Prefect is a Python-native workflow orchestrator popular in ML and data
engineering. Its decorator-based API (`@flow`, `@task`) is the closest
natural match to Chio's decorator pattern (`@chio_requires`, `@chio_budget`).

The integration thesis: **Prefect tasks that invoke tools or access
sensitive resources should be Chio-governed.** Each task execution gets
capability validation and a signed receipt. Flows aggregate receipts into
a workflow-level attestation.

### Where Chio Fits

| Prefect Concept | Chio Concept | Integration Point |
|-----------------|-------------|-------------------|
| `@flow` | WorkflowGrant | Flow run acquires a scoped grant |
| `@task` | Tool invocation | Task run evaluated against capability |
| Task retry | Re-evaluation | Chio re-evaluates on each retry attempt |
| Concurrency limits | Budget guards | Chio budgets complement Prefect limits |
| Artifacts | Receipts | Chio receipt attached as task artifact |
| Events | Receipt events | Chio receipts emitted as Prefect events |

## 2. Architecture

```
Prefect Worker / Agent
+-------------------------------------------------------+
|                                                       |
|  @flow                                                |
|  def agent_pipeline():         Chio Sidecar (:9090)    |
|      @task                     +-------------------+  |
|      def search():  ---------> | evaluate(search)  |  |
|          ...                   | guard pipeline     |  |
|      @task                     | sign receipt       |  |
|      def analyze(): ---------> | evaluate(analyze)  |  |
|          ...                   +-------------------+  |
|                                                       |
+-------------------------------------------------------+
```

## 3. Integration Model

### 3.1 Task Decorator (`@chio_task`)

Combines Prefect's `@task` with Chio capability enforcement:

```python
from prefect import flow, task
from chio_prefect import chio_task, chio_flow

@chio_task(
    scope="tools:search",
    guards=["rate-limit"],
    budget={"max_calls": 100},
)
def search_documents(query: str) -> list[dict]:
    """Search is Chio-governed -- capability checked before execution."""
    return search_engine.search(query)


@chio_task(scope="tools:analyze")
def analyze_results(documents: list[dict]) -> dict:
    """Analysis task with its own capability scope."""
    return analyzer.run(documents)


@chio_flow(scope="agent:research-pipeline")
def research_pipeline(query: str) -> dict:
    """Flow-level grant scopes all tasks within."""
    docs = search_documents(query)
    analysis = analyze_results(docs)
    return analysis
```

### 3.2 Implementation

```python
import functools
from prefect import task, get_run_logger
from prefect.artifacts import create_markdown_artifact
from chio_sdk import ChioClient

def chio_task(scope: str, guards: list[str] | None = None, budget: dict | None = None):
    """Decorator that wraps a Prefect task with Chio capability enforcement."""

    def decorator(fn):
        @task(name=fn.__name__)
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            arc = ChioClient()
            logger = get_run_logger()

            verdict = await arc.evaluate(
                tool=fn.__name__,
                scope=scope,
                arguments={"args": args, "kwargs": kwargs},
                guards=guards,
                budget=budget,
            )

            if verdict.denied:
                logger.error(f"Chio denied {fn.__name__}: {verdict.reason}")
                # Create artifact recording the denial
                await create_markdown_artifact(
                    key=f"chio-denial-{fn.__name__}",
                    markdown=f"## Chio Capability Denied\n\n"
                             f"- **Tool**: {fn.__name__}\n"
                             f"- **Scope**: {scope}\n"
                             f"- **Reason**: {verdict.reason}\n"
                             f"- **Receipt**: `{verdict.receipt_id}`\n",
                )
                raise PermissionError(f"Chio denied: {verdict.reason}")

            result = fn(*args, **kwargs)

            # Record receipt as Prefect artifact
            receipt = await arc.record(verdict=verdict)
            await create_markdown_artifact(
                key=f"chio-receipt-{fn.__name__}",
                markdown=f"## Chio Receipt\n\n"
                         f"- **Receipt ID**: `{receipt.receipt_id}`\n"
                         f"- **Tool**: {fn.__name__}\n"
                         f"- **Scope**: {scope}\n",
            )

            return result

        return wrapper
    return decorator
```

### 3.3 Flow-Level Grants

```python
def chio_flow(scope: str):
    """Decorator that acquires a workflow-level Chio grant for the flow."""

    def decorator(fn):
        @flow(name=fn.__name__)
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            arc = ChioClient()

            grant = await arc.acquire_grant(scope=scope)
            # Store grant in Prefect runtime context for tasks to access
            from prefect.context import get_run_context
            ctx = get_run_context()
            ctx.task_run.tags.add(f"arc:grant:{grant.token}")

            try:
                result = await fn(*args, **kwargs)
            finally:
                await arc.release_grant(grant)

            return result

        return wrapper
    return decorator
```

### 3.4 Retry Behavior

Prefect retries are re-evaluations. If a capability was revoked between
retries, the task fails with a non-retryable error:

```python
@chio_task(
    scope="tools:external-api",
    guards=["rate-limit"],
)
@task(retries=3, retry_delay_seconds=30)
def call_external_api(payload: dict) -> dict:
    # On retry, chio_task re-evaluates the capability.
    # If the rate-limit guard now rejects (budget exhausted),
    # the retry stops with PermissionError (non-retryable).
    return api_client.post(payload)
```

## 4. Prefect Events Integration

Chio receipts emitted as Prefect events enable automation triggers:

```python
from prefect.events import emit_event

# Inside chio_task wrapper, after recording receipt:
emit_event(
    event="chio.receipt.created",
    resource={"prefect.resource.id": f"arc.receipt.{receipt.receipt_id}"},
    payload={
        "receipt_id": receipt.receipt_id,
        "tool": fn.__name__,
        "scope": scope,
        "verdict": "allow",
    },
)

# Denial events:
emit_event(
    event="chio.capability.denied",
    resource={"prefect.resource.id": f"arc.denial.{verdict.receipt_id}"},
    payload={
        "tool": fn.__name__,
        "scope": scope,
        "reason": verdict.reason,
    },
)
```

### Automation Triggers

```yaml
# Prefect automation: pause deployments on repeated Chio denials
automations:
  - name: chio-denial-circuit-breaker
    trigger:
      type: event
      match:
        event: arc.capability.denied
      threshold: 5
      within: 300  # 5 denials in 5 minutes
    actions:
      - type: pause-deployment
        deployment_id: "{{ deployment.id }}"
```

## 5. Prefect Blocks for Chio Configuration

```python
from prefect.blocks.core import Block

class ChioConfig(Block):
    """Prefect Block storing Chio sidecar configuration."""

    _block_type_name = "Chio Config"

    sidecar_url: str = "http://127.0.0.1:9090"
    default_scope: str = "tools:*"
    receipt_sink: str = "local"
    policy_path: str | None = None

    def get_client(self) -> ChioClient:
        return ChioClient(base_url=self.sidecar_url)
```

## 6. Package Structure

```
sdks/python/chio-prefect/
  pyproject.toml            # deps: chio-sdk-python, prefect>=3.0
  src/chio_prefect/
    __init__.py
    decorators.py           # chio_task, chio_flow
    events.py               # Prefect event emission
    blocks.py               # ChioConfig block
    artifacts.py            # Receipt artifact formatting
  tests/
    test_arc_task.py
    test_flow_grant.py
    test_retry.py
```

## 7. Open Questions

1. **Prefect Cloud vs. self-hosted.** On Prefect Cloud, the sidecar must
   run in the user's infrastructure (worker/agent). Does the Chio client
   need a remote kernel mode for cloud-hosted workers?

2. **Subflows.** Prefect subflows can run in-process or as separate
   infrastructure. Should subflows inherit the parent flow's grant or
   acquire their own?

3. **Concurrency slots.** Prefect has built-in concurrency limiting via
   tags. Should Chio budgets integrate with Prefect's concurrency system
   or operate independently?
