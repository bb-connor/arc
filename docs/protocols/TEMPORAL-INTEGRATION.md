# Temporal Integration

This document describes the `chio-temporal` Python package
(`sdks/python/chio-temporal`). It gates every Temporal Activity on the Chio
sidecar's mediated caller-delivery route and collects the resulting kernel
receipts per workflow run.

There is no Rust Temporal integration.

## 1. Requirements

- **A sidecar with a caller executor.** The sidecar (`chio api protect`) must
  have a caller executor configured. The only supported way to configure one
  is the approval-authority config (`ProtectApprovalConfig.caller_executor`),
  which also requires an activated replay authority. A sidecar without a
  caller executor rejects `/v1/caller/start`, and the interceptor then
  denies every activity.
- **Matching executor key material on the worker.** The worker host supplies
  a `CallerExecutor` whose `identity` equals the sidecar's configured caller
  executor, plus the pinned kernel public key. This package ships no signer.
- **The sidecar-control token.** `/v1/caller/start` and `/v1/caller/report`
  sit behind the sidecar-control bearer.
- **A complete signed capability token** per workflow (`WorkflowGrant.token`).
  A bare capability id cannot authorize anything.
- **Synchronized clocks.** The report's start and completion times come from
  the worker clock. If the worker clock is behind the kernel, the local
  window check fails. If it is ahead, the kernel rejects the report because
  the completion time is later than its trusted time. The sidecar answers
  that with a generic HTTP 409, and the interceptor's error names clock skew
  as a cause.

## 2. Topology

The sidecar runs next to the Activity worker. Workflow workers never call the
sidecar. The Activity worker is the enforcement point and acts as the caller
executor.

```
Activity worker                          Chio sidecar (chio api protect)
+------------------------------+         +------------------------------+
| ChioActivityInterceptor      |  HTTP   | /v1/evaluate        reserve  |
|   CallerExecutor (host keys) | ------> | /v1/caller/start    commit   |
|   control token              |         | /v1/caller/report   finalize |
+------------------------------+         +------------------------------+
```

## 3. Activity lifecycle

For each activity attempt, `ChioActivityInterceptor`:

1. **Reserves.** `POST /v1/evaluate` with the grant's signed token, the
   redacted activity arguments and an attempt-scoped `request_id`. A `deny`
   or `pending_approval` raises a non-retryable
   `ApplicationError(type="ChioCapabilityDenied")`. The activity body does not
   run.
2. **Starts.** `POST /v1/caller/start` with the execution nonce and the same
   arguments. The returned dispatch authorization must be signed by the
   pinned kernel key and must bind this executor, request id, capability,
   tool server and activity type. The current time must also fall inside
   its execution window. If any check fails, the activity does not run.
3. **Runs** the activity.
4. **Reports.** `POST /v1/caller/report` with an executor-signed report. The
   report output is `{"outcome": "completed", "result_sha256": ...}` (SHA-256
   of the result's payload bytes under the worker's payload converter) or
   `{"outcome": "failed", "error_type": ...}`. Raw results are not sent. A
   failed activity is still reported so the reservation finalizes, and then
   the original exception is re-raised. The kernel accounts a failure report
   as a completed call whose output is the failure record. Cancellation is
   reported the same way and always propagates as cancellation. A result
   the converter cannot encode is reported as `completed_unencodable` and
   fails the activity non-retryably. An activity that calls
   `activity.raise_complete_async()` is not reported; its hold is left for
   the kernel to expire. A report `deny` withholds the result and raises
   `ChioCapabilityDenied`.

Reservation and terminal receipts are verified before they are recorded:
`kernel_key` must equal the pinned kernel key, the id must be the SHA-256 of
the canonical receipt body, and the signature must verify over the canonical
signing body. A forged receipt fails closed. Synthetic deny receipts built
from an HTTP 403 carry `metadata.synthetic = true` and no kernel signature.

Errors fail closed with `ApplicationError(type="ChioSidecarError")`. Only an
unreachable sidecar before reservation is retryable.

Errors the interceptor itself raises after reservation are non-retryable. That
does not make an activity run at most once. A start-to-close or heartbeat
timeout, or a worker crash after start, makes Temporal retry the activity as a
new attempt. The new attempt gets a new `request_id` and a new reservation, so
the side effects can run again. When the earlier attempt is cancelled in a
live worker, the interceptor still reports it. After a crash nothing is
reported, and that committed hold stays open until the kernel expires or
recovers it.

Pending approvals are not resumed.

## 4. Wiring

```python
from chio_temporal import ChioActivityInterceptor, WorkflowGrant

interceptor = ChioActivityInterceptor(
    executor=my_executor,            # chio_temporal.CallerExecutor
    control_token=SIDECAR_CONTROL_TOKEN,
    chio_client=chio,                # chio_sdk.client.ChioClient
    activity_tool_server_map={"send_email": "email-srv"},
)
interceptor.register_workflow_grant(
    WorkflowGrant(workflow_id="notify-wf-1", token=signed_token, tool_server="email-srv")
)
worker = Worker(client, task_queue="notify", activities=[send_email],
                interceptors=[interceptor])
```

`build_chio_worker(...)` wires the same pieces. It takes either `token` or
`scope` (the latter is minted through `chio_client.create_capability`),
together with `executor` and `control_token`.

`CallerExecutor` is a protocol:

| Member | Meaning |
|--------|---------|
| `identity` | `{"executor_id", "public_key", "key_epoch"}`, equal to the sidecar's caller executor |
| `kernel_public_key` | Pinned kernel key that must sign every dispatch authorization |
| `sign(message)` | Sign canonical report bytes with the executor key |
| `verify_kernel_signature(message, signature)` | Verify an authorization signature against the pinned kernel key |

### Activity-scoped grants

`WorkflowGrant.attenuate_for_activity(chio, new_scope=...)` mints a strictly
narrower child token. You can register it for one activity type with
`register_activity_grant_override`. The interceptor re-checks
`child.scope ⊆ parent.scope` before reserving.

## 5. WorkflowReceipt

`WorkflowReceipt` is an **unsigned, in-memory** aggregate, keyed by
`(workflow_id, run_id)`. It lives in worker memory until
`flush_workflow_receipt`, which hands the envelope to the optional
`receipt_sink`. A worker restart loses it. The only signed artifacts are the
per-step kernel receipts inside it.

Each step records the activity type, id and attempt, and the terminal kernel
receipt. That is the deny or pending receipt when the activity never ran,
otherwise the receipt from finalizing the report. Executed steps also carry
`reservation_receipt_id`. The envelope version is `chio-temporal/v1`.

## 6. Saga compensation

A denial is a non-retryable `ApplicationError` whose `type` is
`ChioCapabilityDenied` (`chio_temporal.DENIED_ERROR_TYPE`). Workflows can
match on it to run compensations:

```python
try:
    credit = await workflow.execute_activity(
        credit_account,
        args=[transfer.destination, transfer.amount],
        start_to_close_timeout=timedelta(seconds=30),
    )
except ActivityError as e:
    cause = e.cause
    if isinstance(cause, ApplicationError) and cause.type == "ChioCapabilityDenied":
        await workflow.execute_activity(
            credit_account,
            args=[transfer.source, transfer.amount],
            start_to_close_timeout=timedelta(seconds=30),
        )
    raise
```

`ChioSidecarError` means the lifecycle could not complete. Treat it as an
infrastructure failure, not a policy decision.

## 7. Limits

- There is no durable executor ledger. A worker that dies between start and
  report leaves the committed hold for the kernel to expire or recover.
- Canonical JSON is reproduced locally only for strings, integers, booleans
  and null. Authorizations or reports containing floats fail closed.
- The result digest covers payload-converter bytes. A payload codec (for
  example encryption) is not applied.
- Capability revocation does not cancel a running workflow. It denies the
  next reservation or start.

## 8. Package structure

```
sdks/python/chio-temporal/
  src/chio_temporal/
    interceptor.py   # ChioActivityInterceptor, mediated lifecycle
    executor.py      # CallerExecutor protocol, canonical JSON
    grants.py        # WorkflowGrant
    receipt.py       # WorkflowReceipt, WorkflowStepReceipt
    worker.py        # build_chio_worker
    errors.py
  tests/
    _mediated_contract.py   # contract double of the mediated route
    test_interceptor.py
    test_redaction.py
    test_workflow_receipt.py
```

The tests run against the contract double and against the real `ChioClient`
over mocked HTTP. They do not start a live sidecar.

## 9. Open questions

1. **Schedule-scoped grants.** Should a Temporal Schedule hold one grant for
   all spawned workflows, or should each workflow acquire its own?
2. **Child workflow delegation.** Should a child workflow inherit the parent
   grant, or request an attenuated one?
3. **Approval resume.** Should a `pending_approval` reservation pause the
   activity and resume on a Temporal Signal?
4. **Durable executor claims.** Should the worker keep a durable executor
   ledger so a crash between start and report can be recovered?
