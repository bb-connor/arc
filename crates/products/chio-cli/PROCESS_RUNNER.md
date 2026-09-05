# Run a worker application

`chio process run` launches a declared Linux worker application against an
initialized process host. It starts ready workers up to a concurrency ceiling,
waits for dependencies to complete, and restarts failed workers within a
persistent attempt budget. Each attempt uses the same Chio process and the
application's existing checkpoint and logical operation identities.

## Declare and run

First [initialize a process host](PROCESS_HOST.md) with its policy, tools,
mailboxes and capability tree. Save a plan selecting existing process IDs:

```json
{
  "schema": "chio.process.run.v1",
  "max_parallel": 2,
  "workers": [
    {
      "process": "researcher",
      "command": ["/absolute/path/to/python", "/absolute/path/to/research.py"],
      "cwd": "/absolute/path/to/application",
      "input": {"checkpoint": "/private/research.db"},
      "depends_on": [],
      "max_attempts": 3,
      "timeout_seconds": 300
    },
    {
      "process": "publisher",
      "command": ["/absolute/path/to/python", "/absolute/path/to/publish.py"],
      "cwd": "/absolute/path/to/application",
      "input": {"checkpoint": "/private/publisher.db"},
      "depends_on": ["researcher"],
      "max_attempts": 3,
      "timeout_seconds": 300
    }
  ]
}
```

```bash
chio process run --state /private/host --plan worker-plan.json
```

Use a short state path to leave room for the Unix socket filename. A host
admits one immutable run plan. There may be 1-128 distinct workers, 1-32
concurrent workers, 1-16 lifetime attempts per worker and a 1-3600 second
deadline per attempt. Process IDs must already exist. Dependencies can be
listed in any order; unknown, duplicate and cyclic dependencies are rejected.
Commands use an absolute executable and literal argument vector, with no
shell expansion. Working directories are absolute. Plan JSON is limited to
one MiB. `input` defaults to null and `depends_on` defaults to an empty list.

## Worker bootstrap

The runner writes one JSON object to the worker's private stdin, then closes
stdin. It contains `schema: "chio.process.worker-bootstrap.v1"`, the ordinary
private `connection` descriptor, a one-based `attempt`, and the plan's `input`.
Descriptors do not need to be written to files.

```python
import json
import sys
from chio_process import ProcessClient

bootstrap = json.load(sys.stdin)
assert bootstrap["schema"] == "chio.process.worker-bootstrap.v1"
connection = bootstrap["connection"]
client = ProcessClient(connection["socket_path"], connection["credential"])
# Resume your existing application checkpoint, retaining original operation keys.
result = client.invoke("handoff-result", "chio-ipc", "send_reviews", {
    "message_key": "review", "payload": {"text": "Ready"},
})
```

Retain the application's durable planning checkpoints. Attempt numbers are
diagnostic information and must never enter logical tool-operation keys,
message keys, graph thread IDs or external idempotency keys. Restarting a
process does not authorize a new tool effect. The runner does not rewrite
application planning or implement tool dispatch/replay.

Workers inherit the host environment. The application owns provider setup,
module paths and model configuration. Keep connection credentials outside
model messages, graph checkpoints and tracing configuration. Provider API
calls outside the worker protocol remain outside Chio's tool-call budgets.

## Completion and recovery

Exit zero completes a worker and releases its dependents. Other exits, signals,
startup failures and deadlines consume an attempt. Failed attempts retry after
one second while budget remains. The runner stops when a worker exhausts its
budget; pending dependents do not launch. Exit zero establishes process
completion, not correct model findings or verified external effects. An
application should verify its outputs and original receipts before claiming
its own task complete.

Run the same command after a host interruption. `runner.db` binds the plan,
version, qualified authority and signing key. It reserves attempts before
launching workers and records completion only after observing their exit.
An interrupted attempt counts even if the host died before spawning its
worker. Previously completed workers remain completed. A worker whose exit
was not recorded resumes from its application checkpoint. Attempt limits never
reset on restart, and changing the plan is rejected. An exhausted run is
terminal under this plan; creating fresh state or changing operation keys is
not a safe way to recover an uncertain tool effect.

The exclusive host lock covers startup reconciliation, serving and worker
lifecycle. Each host run uses a fresh socket. Worker credentials rotate on
startup and each attempt, and are revoked after completion and shutdown.
Previously admitted kernel calls can still finish. SIGINT/SIGTERM stop workers
and drain admitted kernel calls. A tool that never returns can keep that drain
open; forced host death leaves durable admission to classify the outcome.
Cancelled Chio processes stop the application, and their active direct workers
are terminated. Host interruption does not permanently cancel Chio identities.

Native mailbox and external tool effects still use the kernel's existing
durable outcome rules. If the host dies after an effect but before recording
its outcome, resumed workers cannot automatically redispatch it. A bounded
restart loop can end incomplete while preserving the original effect identity.

## Persistence and operating boundary

The host keeps private `runner.db`, `run-sockets/` and `run-logs/` state.
Successful command output is one `chio.process.run-report.v1` JSON object
with completion state and each worker's attempt count/outcome. A failed run
can also emit this report before exiting nonzero. Per-attempt stdout/stderr
logs retain at most 64 KiB each and replace that attempt's exact bearer token
with `[REDACTED]`. Excess bytes are drained and discarded. Logs are private
diagnostics, can contain application data, and are not signed receipt evidence.
An abrupt host death may lose captured logs. Preserve the complete host and
application checkpoint state for recovery.

The runner tracks direct worker processes. Before exec it configures Linux
[parent-death signaling](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html)
and checks for a parent-exit race. Use ordinary unprivileged worker programs;
privilege-changing execs can clear that signal. Descendants created by worker
code and MCP server isolation remain deployment responsibilities. The runner
does not provide an OS sandbox, resource cgroups, distributed placement or a
multi-host lease. Same-user processes can access each other's files. Code,
dependencies and inherited environment remain trusted deployment inputs; the
plan hash does not attest executable bytes. Capabilities still expire under
the host's original policy and are not renewed by worker restarts.

## Qualification

`cargo test -p chio-cli --test process_host` uses real Python workers and MCP
subprocesses. Runner cases cover automatic retry, a killed host and direct
worker termination, stale credential rejection, original receipt recovery,
dependency ordering, concurrent-worker ceilings, deadlines, persistent attempt
exhaustion, cancelled workers, bounded logs, plan drift and uncertain effects.
The [repository review](../../../examples/repository-review/README.md) also
runs its existing LangGraph workers through this native runner and verifies
handoff and publication recovery in inventory and scripted-model profiles.
