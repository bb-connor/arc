# chio-temporal

Temporal integration for the [Chio protocol](../../../spec/PROTOCOL.md).
Plugs into Temporal's Python SDK so every Activity invocation runs
through the Chio sidecar's mediated caller-delivery route (`chio api
protect`): reserve, start, run, report. Denied or pending activities
raise non-retryable `temporalio.exceptions.ApplicationError`, and each
workflow run collects an unsigned, in-memory `WorkflowReceipt`
aggregate of the per-activity kernel receipts.

## Install

```bash
uv pip install chio-temporal
# or
pip install chio-temporal
```

The package depends on `chio-sdk-python`, `temporalio>=1.7,<2`, and
`pydantic>=2.5`.

## Quickstart

```python
import asyncio
import os
from datetime import timedelta

from chio_sdk.client import ChioClient
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_temporal import ChioActivityInterceptor, WorkflowGrant, build_chio_worker
from temporalio import activity, workflow
from temporalio.client import Client


@activity.defn
async def send_email(to: str, body: str) -> str:
    return f"sent to {to}"


@workflow.defn
class NotifyWorkflow:
    @workflow.run
    async def run(self, to: str) -> str:
        return await workflow.execute_activity(
            send_email,
            args=[to, "hello"],
            start_to_close_timeout=timedelta(seconds=30),
        )


SIDECAR_CONTROL_TOKEN = os.environ["CHIO_SIDECAR_CONTROL_TOKEN"]
my_executor = load_caller_executor()  # your chio_temporal.CallerExecutor


async def main() -> None:
    client = await Client.connect("localhost:7233")
    async with ChioClient("http://127.0.0.1:9090") as chio:
        worker, interceptor, grant = await build_chio_worker(
            client,
            task_queue="notify",
            activities=[send_email],
            workflows=[NotifyWorkflow],
            workflow_id="notify-wf-1",
            chio_client=chio,
            executor=my_executor,  # implements chio_temporal.CallerExecutor
            control_token=SIDECAR_CONTROL_TOKEN,
            scope=ChioScope(
                grants=[
                    ToolGrant(
                        server_id="email-srv",
                        tool_name="send_email",
                        operations=[Operation.INVOKE],
                    )
                ]
            ),
            subject="agent:notify",
            tool_server="email-srv",
        )
        try:
            async with worker:
                handle = await client.start_workflow(
                    NotifyWorkflow.run,
                    "alice@example.com",
                    id="notify-wf-1",
                    task_queue="notify",
                )
                await handle.result()
        finally:
            receipt = interceptor.finalize_workflow(
                workflow_id="notify-wf-1", outcome="success"
            )
            await interceptor.flush_workflow_receipt(workflow_id="notify-wf-1")


asyncio.run(main())
```

At runtime:

* `POST /v1/evaluate` reserves the call with the workflow's complete
  signed capability token. `deny` or `pending_approval` raises
  `ApplicationError(type="ChioCapabilityDenied", non_retryable=True)`
  and the activity body never runs.
* `POST /v1/caller/start` commits the reservation. The interceptor
  checks the returned dispatch authorization against the pinned kernel
  key, its own executor identity, the activity's tool and capability,
  and the authorization's time window before the body runs.
* After the body returns or raises, `POST /v1/caller/report` delivers an
  executor-signed report so the reservation finalizes. The report output
  is `{"outcome": "completed", "result_sha256": ...}` (SHA-256 of the
  result's payload bytes under the worker's payload converter) or
  `{"outcome": "failed", "error_type": ...}`. Raw results are not sent.
  The kernel accounts a failure report as a completed call whose output
  is the failure record. If the result cannot be encoded, the outcome
  `completed_unencodable` is reported and the activity fails
  non-retryably. Cancellation is reported and still propagates as
  cancellation. An activity that calls `activity.raise_complete_async()`
  is not reported, and its hold is left for the kernel to expire.
* A `deny` from the report withholds the result and raises
  `ChioCapabilityDenied`. Any sidecar, transport or contract error stops
  the activity with `ApplicationError(type="ChioSidecarError")`. Only an
  unreachable sidecar before reservation is retryable.
* Reservation and terminal receipts must be signed by the pinned kernel
  key and be content-addressed. Otherwise the activity fails closed and
  nothing is recorded. Synthetic deny receipts built from an HTTP 403
  carry `metadata.synthetic = true` and no kernel signature.
* The terminal kernel receipt for each attempt is recorded on the
  `WorkflowReceipt` step and forwarded to the configured `receipt_sink`
  on `flush_workflow_receipt`.

## Executor and control token

The interceptor is the caller executor for the sidecar's
`/v1/caller/start` and `/v1/caller/report` routes, so it needs:

* `control_token` -- the sidecar-control bearer token.
* `executor` -- an object implementing `chio_temporal.CallerExecutor`:
  `identity` (the `executor_id` / `public_key` / `key_epoch` the sidecar
  was configured with), `kernel_public_key` (pinned), `sign(message)`
  and `verify_kernel_signature(message, signature)`. Key material is
  supplied by the worker host; this package ships no signer
  implementation.

The sidecar must be configured with that caller executor. A sidecar
without one rejects `/v1/caller/start`, and the interceptor then denies
every activity.

Limits, stated plainly:

* There is no durable executor ledger. A worker that dies between start
  and report leaves the committed hold for the kernel to expire or
  recover.
* Canonical JSON is reproduced locally for strings, integers, booleans
  and null only; an authorization or report containing floats fails
  closed.
* Pending approvals are not resumed; the activity fails non-retryably.
* Retries are not at-most-once. Errors the interceptor raises after
  reservation are non-retryable. That does not make an activity run at
  most once. A start-to-close or heartbeat timeout, or a worker crash
  after start, makes Temporal retry the activity as a new attempt. The
  new attempt gets a new `request_id` and a new reservation, so the side
  effects can run again. When the earlier attempt is cancelled in a live
  worker, the interceptor still reports it. After a crash nothing is
  reported, and that committed hold stays open until the kernel expires
  or recovers it.
* Clocks must be synchronized. The report's start and completion times
  come from the worker clock. A worker clock behind the kernel fails the
  local window check; a worker clock ahead makes the kernel reject the
  report (HTTP 409), and the interceptor names that cause in its error.

## Attenuated activity-scoped grants

The default `WorkflowGrant` applies to every activity in the workflow.
For finer-grained control, attenuate the grant for a specific activity
type and register it as an override:

```python
from chio_temporal import WorkflowGrant

child_scope = ChioScope(grants=[
    ToolGrant(
        server_id="email-srv",
        tool_name="send_email",
        operations=[Operation.INVOKE],
    ),
])
child_grant = await grant.attenuate_for_activity(chio, new_scope=child_scope)

interceptor.register_activity_grant_override(
    "send_email", lambda _info: child_grant
)
```

The child capability is always `child ⊆ parent`; the SDK raises
`ChioValidationError` if you try to broaden scope, and the interceptor
re-checks the subset invariant before evaluating.

## WorkflowReceipt envelope

The aggregate is **unsigned** and lives in worker memory until
`flush_workflow_receipt`; a worker restart loses it. Only the per-step
kernel receipts it embeds are signed. The envelope (version
`chio-temporal/v1`):

```json
{
  "version": "chio-temporal/v1",
  "workflow_id": "notify-wf-1",
  "run_id": "...",
  "parent_workflow_ids": [],
  "started_at": 1713225600,
  "completed_at": 1713225612,
  "outcome": "success",
  "step_count": 2,
  "allow_count": 2,
  "deny_count": 0,
  "steps": [
    {"activity_type": "send_email", "activity_id": "act-1", "attempt": 1,
     "reservation_receipt_id": "...", "receipt": {...}},
    ...
  ],
  "metadata": {}
}
```

`to_json()` returns this payload with sorted keys so Merkle chaining
and content-hash verification are deterministic across runs.

## Error types

* `ChioTemporalError` -- raised when the Chio kernel denies an Activity.
  Carries `activity_type`, `activity_id`, `workflow_id`, `run_id`,
  `guard`, `reason`, `receipt_id`. The interceptor wraps this in a
  non-retryable `ApplicationError` before handing control back to
  Temporal.
* `ChioTemporalConfigError` -- raised on invalid configuration (no
  `WorkflowGrant` for a workflow_id, missing `executor` or
  `control_token`, attenuation beyond the parent grant's scope).
* `ApplicationError(type="ChioSidecarError")` (`SIDECAR_ERROR_TYPE`) --
  the mediated lifecycle could not complete; the activity did not run,
  or its result was withheld.

## HITL approval path

A `pending_approval` reservation stops the activity non-retryably.
Pausing on approval and resuming via Temporal Signal is not
implemented.

## Reference

See
[`docs/protocols/TEMPORAL-INTEGRATION.md`](../../../docs/protocols/TEMPORAL-INTEGRATION.md)
for the full integration design (intercept points, grant topology,
receipt aggregation, saga compensation).

## Development

```bash
uv venv --python 3.11
uv pip install -e '.[dev]'
uv pip install -e ../chio-sdk-python

uv run pytest
uv run mypy src/
uv run ruff check src/ tests/
```

The tests run against a contract double of the mediated route
(`tests/_mediated_contract.py`) and the real `ChioClient` over mocked
HTTP. They do not start a live sidecar.
