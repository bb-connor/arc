# Prefect Integration: ML Pipeline Task Security

> **Status**: Tier 2 -- proposed April 2026
> **Priority**: Medium -- Prefect's `@task` decorator model maps cleanly to
> ARC's `@arc_requires` pattern. Growing adoption in ML/AI pipelines where
> agent-driven data processing needs tool-level governance.

## 1. Why Prefect

Prefect is a Python-native workflow orchestrator popular in ML and data
engineering. Its decorator-based API (`@flow`, `@task`) is the closest
natural match to ARC's decorator pattern (`@arc_requires`, `@arc_budget`).

The integration thesis: **Prefect tasks that invoke tools or access
sensitive resources should be ARC-governed.** Each task execution gets
capability validation and a signed receipt. Flows aggregate receipts into
a workflow-level attestation.

### Where ARC Fits

| Prefect Concept | ARC Concept | Integration Point |
|-----------------|-------------|-------------------|
| `@flow` | WorkflowGrant | Flow run acquires a scoped grant |
| `@task` | Tool invocation | Task run evaluated against capability |
| Task retry | Re-evaluation | ARC re-evaluates on each retry attempt |
| Concurrency limits | Budget guards | ARC budgets complement Prefect limits |
| Artifacts | Receipts | ARC receipt attached as task artifact |
| Events | Receipt events | ARC receipts emitted as Prefect events |

## 2. Architecture

```
Prefect Worker / Agent
+-------------------------------------------------------+
|                                                       |
|  @flow                                                |
|  def agent_pipeline():         ARC Sidecar (:9090)    |
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

### 3.1 Task Decorator (`@arc_task`)

Combines Prefect's `@task` with ARC capability enforcement:

```python
from prefect import flow, task
from arc_prefect import arc_task, arc_flow

@arc_task(
    scope="tools:search",
    guards=["rate-limit"],
    budget={"max_calls": 100},
)
def search_documents(query: str) -> list[dict]:
    """Search is ARC-governed -- capability checked before execution."""
    return search_engine.search(query)


@arc_task(scope="tools:analyze")
def analyze_results(documents: list[dict]) -> dict:
    """Analysis task with its own capability scope."""
    return analyzer.run(documents)


@arc_flow(scope="agent:research-pipeline")
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
from arc_sdk import ArcClient

def arc_task(scope: str, guards: list[str] | None = None, budget: dict | None = None):
    """Decorator that wraps a Prefect task with ARC capability enforcement."""

    def decorator(fn):
        @task(name=fn.__name__)
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            arc = ArcClient()
            logger = get_run_logger()

            verdict = await arc.evaluate(
                tool=fn.__name__,
                scope=scope,
                arguments={"args": args, "kwargs": kwargs},
                guards=guards,
                budget=budget,
            )

            if verdict.denied:
                logger.error(f"ARC denied {fn.__name__}: {verdict.reason}")
                # Create artifact recording the denial
                await create_markdown_artifact(
                    key=f"arc-denial-{fn.__name__}",
                    markdown=f"## ARC Capability Denied\n\n"
                             f"- **Tool**: {fn.__name__}\n"
                             f"- **Scope**: {scope}\n"
                             f"- **Reason**: {verdict.reason}\n"
                             f"- **Receipt**: `{verdict.receipt_id}`\n",
                )
                raise PermissionError(f"ARC denied: {verdict.reason}")

            result = fn(*args, **kwargs)

            # Record receipt as Prefect artifact
            receipt = await arc.record(verdict=verdict)
            await create_markdown_artifact(
                key=f"arc-receipt-{fn.__name__}",
                markdown=f"## ARC Receipt\n\n"
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
def arc_flow(scope: str):
    """Decorator that acquires a workflow-level ARC grant for the flow."""

    def decorator(fn):
        @flow(name=fn.__name__)
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            arc = ArcClient()

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
@arc_task(
    scope="tools:external-api",
    guards=["rate-limit"],
)
@task(retries=3, retry_delay_seconds=30)
def call_external_api(payload: dict) -> dict:
    # On retry, arc_task re-evaluates the capability.
    # If the rate-limit guard now rejects (budget exhausted),
    # the retry stops with PermissionError (non-retryable).
    return api_client.post(payload)
```

## 4. Prefect Events Integration

ARC receipts emitted as Prefect events enable automation triggers:

```python
from prefect.events import emit_event

# Inside arc_task wrapper, after recording receipt:
emit_event(
    event="arc.receipt.created",
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
    event="arc.capability.denied",
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
# Prefect automation: pause deployments on repeated ARC denials
automations:
  - name: arc-denial-circuit-breaker
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

## 5. Prefect Blocks for ARC Configuration

```python
from prefect.blocks.core import Block

class ArcConfig(Block):
    """Prefect Block storing ARC sidecar configuration."""

    _block_type_name = "ARC Config"

    sidecar_url: str = "http://127.0.0.1:9090"
    default_scope: str = "tools:*"
    receipt_sink: str = "local"
    policy_path: str | None = None

    def get_client(self) -> ArcClient:
        return ArcClient(base_url=self.sidecar_url)
```

## 6. Package Structure

```
sdks/python/arc-prefect/
  pyproject.toml            # deps: arc-sdk-python, prefect>=3.0
  src/arc_prefect/
    __init__.py
    decorators.py           # arc_task, arc_flow
    events.py               # Prefect event emission
    blocks.py               # ArcConfig block
    artifacts.py            # Receipt artifact formatting
  tests/
    test_arc_task.py
    test_flow_grant.py
    test_retry.py
```

## 7. Open Questions

1. **Prefect Cloud vs. self-hosted.** On Prefect Cloud, the sidecar must
   run in the user's infrastructure (worker/agent). Does the ARC client
   need a remote kernel mode for cloud-hosted workers?

2. **Subflows.** Prefect subflows can run in-process or as separate
   infrastructure. Should subflows inherit the parent flow's grant or
   acquire their own?

3. **Concurrency slots.** Prefect has built-in concurrency limiting via
   tags. Should ARC budgets integrate with Prefect's concurrency system
   or operate independently?
