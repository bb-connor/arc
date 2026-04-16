# Temporal Integration: Durable Agent Workflow Security

> **Status**: Tier 1 -- proposed April 2026
> **Priority**: High -- durable workflows are the emerging production pattern
> for multi-step agent systems. Temporal's Activity model maps directly to
> ARC's capability-bounded tool invocations.

## 1. Why Temporal

Temporal is becoming the default runtime for production agent orchestration.
Its programming model -- durable Workflows composed of retriable Activities --
maps naturally to the agent pattern of "plan a sequence of tool calls, execute
them with retry, roll back on failure."

ARC already has `arc-workflow` for ordered tool sequences with `SkillGrant`,
`WorkflowAuthority`, and `WorkflowReceipt`. Temporal provides the durable
execution substrate that `arc-workflow` does not: persistence, retry with
backoff, saga compensation, visibility, and multi-worker distribution.

The integration thesis: **every Temporal Activity that performs a tool call
should pass through the ARC kernel for capability validation and receipt
signing.** Workflow-level grants scope what the entire workflow can do;
Activity-level checks enforce it per step.

### What ARC Adds to Temporal

| Temporal alone | Temporal + ARC |
|----------------|----------------|
| Activities retry on failure | Activities denied before execution if capability revoked |
| Workflow history is append-only | Receipts are Merkle-committed and cryptographically signed |
| Authorization is per-namespace/queue | Authorization is per-tool, per-scope, time-bounded |
| Saga compensation is developer-defined | Revoked capabilities trigger automatic workflow cancellation |
| Visibility queries show workflow state | Receipt log provides cross-workflow audit trail |

## 2. Architecture

```
+------------------------------------------------------------------+
|  Temporal Cluster                                                |
|  +-----------------------------+  +----------------------------+ |
|  |  Workflow Worker             |  |  Activity Worker           | |
|  |                              |  |                            | |
|  |  @workflow.defn              |  |  @activity.defn            | |
|  |  class AgentWorkflow:        |  |  async def call_tool():    | |
|  |    await workflow.execute(   |  |    arc = ArcActivityCtx()  | |
|  |      call_tool, ...)         |  |    result = await arc(     | |
|  |                              |  |      tool, args, cap)      | |
|  +-----------------------------+  +-------------+--------------+ |
|                                                  |                |
+--------------------------------------------------+----------------+
                                                   |
                                          HTTP to sidecar
                                                   |
                                    +--------------v--------------+
                                    |       ARC Kernel Sidecar     |
                                    |  Capability | Guard | Receipt|
                                    +------------------------------+
```

### Deployment Topology

The ARC sidecar runs alongside the Activity worker (same pod in K8s, same
host in VM deployments). Workflow workers do not call the sidecar directly --
they orchestrate; Activity workers execute and are the enforcement point.

```
Pod / Host
+-----------------------------------------+
|  Activity Worker  <-->  ARC Sidecar      |
|  (port 7233)           (port 9090)       |
+-----------------------------------------+
```

## 3. Integration Model

### 3.1 Python SDK (`arc-temporal`)

The integration wraps Temporal's Activity context with ARC capability
validation. Two layers:

**Activity Interceptor** -- automatic, zero-code-change enforcement:

```python
from arc_temporal import ArcActivityInterceptor

worker = Worker(
    client,
    task_queue="agent-tasks",
    workflows=[AgentWorkflow],
    activities=[call_tool, read_database, send_email],
    interceptors=[ArcActivityInterceptor(
        sidecar_url="http://127.0.0.1:9090",
        # Map activity names to ARC tool scopes
        scope_map={
            "call_tool": "tools:invoke",
            "read_database": "db:read",
            "send_email": "email:send",
        },
    )],
)
```

**Explicit context** -- for fine-grained control within activities:

```python
from temporalio import activity
from arc_temporal import ArcActivityContext

@activity.defn
async def call_tool(tool_name: str, arguments: dict) -> dict:
    arc = ArcActivityContext.from_current()

    # Validates capability, runs guards, returns receipt
    result = await arc.invoke(
        tool=tool_name,
        arguments=arguments,
        scope="tools:invoke",
    )

    return result.payload
```

### 3.2 Workflow-Level Capability Grants

A `WorkflowGrant` scopes the entire workflow execution. Individual Activity
invocations must fall within this envelope.

```python
from arc_temporal import WorkflowGrant

@workflow.defn
class AgentWorkflow:
    @workflow.run
    async def run(self, task: AgentTask) -> AgentResult:
        # Acquire a workflow-scoped grant from the capability authority
        grant = await workflow.execute_activity(
            acquire_workflow_grant,
            args=[task.agent_id, task.requested_scopes],
            start_to_close_timeout=timedelta(seconds=30),
        )

        # All subsequent activities inherit this grant's scope ceiling
        # The interceptor attaches grant.token to each activity context
        workflow.set_query_handler("arc_grant", lambda: grant.token)

        result = await workflow.execute_activity(
            call_tool,
            args=["search", {"query": task.query}],
            start_to_close_timeout=timedelta(minutes=5),
        )

        return AgentResult(payload=result)
```

### 3.3 Capability Revocation and Workflow Cancellation

When a capability is revoked mid-workflow, the interceptor triggers Temporal's
cancellation mechanism:

```python
class ArcActivityInterceptor:
    async def execute_activity(self, input):
        # Check capability before execution
        verdict = await self.sidecar.evaluate(
            tool=input.activity_type,
            scope=self.scope_map.get(input.activity_type),
            token=self._get_grant_token(input),
        )

        if verdict.denied:
            # Raise ApplicationError so Temporal records the denial
            # in workflow history with full ARC context
            raise ApplicationError(
                f"ARC capability denied: {verdict.reason}",
                type="ArcCapabilityDenied",
                non_retryable=True,  # Do not retry denied activities
            )

        result = await self.next.execute_activity(input)

        # Attach receipt to activity completion
        activity.info().heartbeat(verdict.receipt_id)
        return result
```

### 3.4 Receipt Integration with Workflow History

Each Activity completion carries an ARC receipt ID. The workflow receipt
aggregates all step receipts into a single `WorkflowReceipt` on completion:

```python
@activity.defn
async def finalize_workflow_receipt(
    receipt_ids: list[str],
    workflow_id: str,
) -> str:
    arc = ArcActivityContext.from_current()
    workflow_receipt = await arc.finalize_workflow(
        step_receipt_ids=receipt_ids,
        workflow_id=workflow_id,
    )
    return workflow_receipt.receipt_id
```

## 4. Saga Compensation with ARC

Temporal sagas (compensating activities) integrate with ARC's revocation model:

```python
@workflow.defn
class TransferWorkflow:
    @workflow.run
    async def run(self, transfer: Transfer) -> TransferResult:
        compensations = []

        # Step 1: debit source
        debit = await workflow.execute_activity(
            debit_account,
            args=[transfer.source, transfer.amount],
            start_to_close_timeout=timedelta(seconds=30),
        )
        compensations.append(("credit_account", transfer.source, transfer.amount))

        # Step 2: credit destination -- if ARC denies this, compensate
        try:
            credit = await workflow.execute_activity(
                credit_account,
                args=[transfer.destination, transfer.amount],
                start_to_close_timeout=timedelta(seconds=30),
            )
        except ApplicationError as e:
            if e.type == "ArcCapabilityDenied":
                # Run compensations in reverse
                for comp in reversed(compensations):
                    await workflow.execute_activity(
                        comp[0], args=list(comp[1:]),
                        start_to_close_timeout=timedelta(seconds=30),
                    )
                raise

        return TransferResult(debit=debit, credit=credit)
```

## 5. Rust SDK (`arc-temporal-core`)

For Rust-native Temporal workers (via `temporal-sdk-core`):

```rust
use arc_temporal::ArcActivityMiddleware;

let worker = Worker::new(
    client,
    WorkerConfig::new("agent-tasks".to_string()),
)
.with_activity_middleware(ArcActivityMiddleware::new(
    "http://127.0.0.1:9090",
    ScopeMap::from([
        ("call_tool", "tools:invoke"),
        ("read_database", "db:read"),
    ]),
));
```

## 6. Observability Bridge

Temporal's visibility API and ARC's receipt log should cross-reference:

| Temporal Concept | ARC Concept | Bridge |
|------------------|-------------|--------|
| Workflow ID | WorkflowReceipt.workflow_id | 1:1 mapping |
| Activity ID | Receipt.invocation_id | Stored in receipt metadata |
| Run ID | WorkflowReceipt.run_id | Temporal-specific field |
| Search Attributes | Receipt tags | Synced via interceptor |
| Workflow History | Receipt Merkle chain | Receipt IDs in activity results |

### Querying

```
# Find all ARC receipts for a Temporal workflow
arc receipt list --meta temporal.workflow_id=<wf-id>

# Find the Temporal workflow for an ARC receipt
temporal workflow show --workflow-id $(arc receipt get <receipt-id> --field meta.temporal.workflow_id)
```

## 7. Package Structure

```
sdks/python/arc-temporal/
  pyproject.toml          # deps: arc-sdk-python, temporalio
  src/arc_temporal/
    __init__.py
    interceptor.py        # ArcActivityInterceptor
    context.py            # ArcActivityContext
    grant.py              # WorkflowGrant helpers
    receipt.py            # Workflow receipt aggregation
  tests/
    test_interceptor.py
    test_saga.py
    test_receipt.py
```

## 8. Open Questions

1. **Schedule-scoped grants.** Should a Temporal Schedule (cron) get a
   long-lived capability grant that covers all its spawned workflows, or
   should each workflow acquire its own?

2. **Child workflow delegation.** When a parent workflow spawns a child,
   should the child inherit the parent's grant or request its own with
   reduced scope (principle of least privilege)?

3. **Signal-triggered re-evaluation.** If a Temporal Signal delivers new
   context (e.g., user approval), should the interceptor re-evaluate
   guards with the updated context?

4. **Multi-cluster.** Temporal supports multi-cluster replication. ARC
   receipt logs are per-kernel. How do we handle receipt continuity across
   Temporal cluster failover?
