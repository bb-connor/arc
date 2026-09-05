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
deadline per attempt. Initially declared process IDs must already exist. Dependencies can be
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

Exit zero completes a worker and releases its dependents. Exit 75 after a
successful `wait_children` call suspends a worker until its recorded children
complete. Every launch, including a cooperative resumption, consumes an
attempt. Other exits, signals,
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

## Adaptive child work

Add `spawn_templates` to a new host configuration. Each template gives a
concrete set of tool routes and a maximum budget share. For example, a
template named `reader` can select only `reports/read`:

```json
"spawn_templates": [{
  "id": "reader",
  "tools": [{"server_id": "reports", "tool_name": "read"}],
  "max_budget_share_bps": 3000
}]
```

The host advertises `chio-process/spawn_reader` and
`chio-process/wait_children`. Grant these routes in the policy and select
them for initial parent processes as needed. The parent must also hold every
route delegated by the chosen template, with delegation authority. A template
cannot grant rights that its caller lacks. Template IDs are unique, at most
48 ASCII letters, digits, underscores or hyphens, with at most 32 templates.
The `chio-process` server ID and process IDs beginning with `dyn_` are reserved
when this profile is enabled.

Add matching `templates` to the run plan. All host templates must have exactly
one runnable definition, including templates a worker may never choose:

```json
"templates": [{
  "id": "reader",
  "command": ["/absolute/path/to/python", "/absolute/path/to/reader.py"],
  "cwd": "/absolute/path/to/application",
  "input": {"repository": "/operator-selected/repository"},
  "max_attempts": 3,
  "timeout_seconds": 300
}]
```

A running worker invokes the template through its ordinary client:

```python
response = client.invoke("review-module-a", "chio-process", "spawn_reader", {
    "input": {"module": "a"}, "budget_share_bps": 2000,
})
assert response["verdict"] == "allow"
child = response["output"]["value"]["process"]
joined = client.invoke("join-module-a-initial", "chio-process", "wait_children", {
    "children": [child],
})
assert joined["verdict"] == "allow"
if not joined["output"]["value"]["complete"]:
    snapshot = client.inspect()["checkpoint"]
    client.checkpoint(snapshot["revision"], {"phase": "waiting", "child": child})
    sys.exit(75)
```

On resumption, read the checkpoint and use a new join poll key to observe
completion. Reusing the initial poll key returns its original pending result
and signed receipt. Preserve spawn keys and arguments across interruption;
an attempt number must not become a new spawn key. Checkpoint continuations
before suspension. Exit 75 without a recorded join is an ordinary failed
attempt. Repeated suspensions cannot bypass the lifetime attempt ceiling.

Child bootstrap `input` is `{"configuration": <template input>, "task":
<guarded submission input>}`. The task is limited to 64 KiB canonical JSON.
Commands, directories, configuration and attempt limits come from the pinned
plan. The child can create grandchildren only if its narrowed grants permit
both the spawn route and the routes it delegates. Children start without a
dependency on their parent's exit, so a failed parent attempt can leave
already committed children eligible to run before its retry.

Joins accept 1-128 unique direct children scheduled by this plan. The host
rejects cycles across declared dependencies and recorded joins before
committing a wait. Waiting parents release their OS slot on exit, allowing
fork/join to complete even at `max_parallel: 1`. Joins remain recorded across
host interruption; pending parents wait for those children before relaunch.
Child failure or cancellation stops the application under the existing runner
failure boundary. There are at most 128 total declared and dynamic workers;
process-tree depth, count, shared logical-call limits and sibling budget
shares can impose lower ceilings. Cancelled slots and shares remain allocated.

The host derives parent identity from kernel-selected invocation context.
Workers cannot supply a parent selector or signing key. Opting into templates
retains private subject signing seeds in `process.db`; preserve and isolate
that complete state along with the host authority. Subject seeds and signed
capability tokens never enter bootstrap input, model tool schemas or status.
Template configuration remains an operator trust decision. `serve` does not
activate these tools; an authenticated attempt must be running under the
bound native runner plan.

Child identity, its signing seed, task/template binding and submission identity
commit in one process-store transaction. The scheduler discovers that durable
work and journals attempts. A spawn may commit before its kernel outcome is
recorded. Host death in that gap leaves the original call unknown and denied
on recovery, while the already committed child can still be scheduled.
Preserve state and inspect it; a new key would request another child. The
process registry does not repair an unknown kernel outcome or redispatch it.

## Persistence and operating boundary

Inspect the application from another terminal while the host is running:

```bash
chio process status --state /private/host
chio process logs --state /private/host --process researcher --attempt 1
```

`status` returns `chio.process.status.v1` JSON. Its `run` snapshot lists each
worker's recorded state, attempts, maximum attempts, most recent outcome and
unfinished dependencies in `waiting_on`. `observed_at_ms` is the snapshot's
Unix timestamp in milliseconds; `run_id` changes when the runner opens a new
run, while `plan_binding` identifies the original plan/authority binding.
The snapshot excludes commands, worker input, environment and credentials.

`host_lock_held` reports whether another process held the exclusive host lock
when sampled. It is not a health check: serving, administration and another
brief status read can hold that lock. Worker states are recorded journal
states, not live OS-process probes. After abrupt host death, a snapshot can
still say `running` with the lock free. Reading status preserves that evidence
and never performs startup reconciliation or changes attempt counts. A null
`run` means no snapshot is available, including hosts created by older builds.

`logs` returns both retained streams in `chio.process.logs.v1` JSON, with each
stream limited to 64 KiB. Logs become available after an attempt finishes;
an interrupted host or an early startup failure may leave no retained logs.
The command does not fall back to a different attempt. JSON escapes terminal
control characters, and the runner's exact credential redaction is preserved.
These remain private application diagnostics, not signed evidence. No worker
credential or running host connection is needed for either local command.

The runner atomically replaces `run-status.json` after journal transitions.
This file is a derived observation, not a recovery input. It may lag a
transition if publication fails; diagnostics never authorize execution or
override `runner.db`. Both readers require existing private state, reject
linked or broadly readable files and bound their reads. They do not construct
a kernel, read signing keys or connect to tool servers.

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
Live and stopped diagnostics tests cover dependency waiting, retry generations,
stale crash snapshots without reconciliation, failed-worker outcomes, credential
redaction, malformed or oversized input and linked/FIFO log rejection.
The [repository review](../../../examples/repository-review/README.md) also
runs its existing LangGraph workers through this native runner and verifies
handoff and publication recovery in inventory and scripted-model profiles.
Its [adaptive application](../../../examples/repository-review/ADAPTIVE.md)
starts with a coordinator and publisher, lets the coordinator choose review
assignments from the captured change inventory, and submits native reviewer
children at runtime. It qualifies durable LangGraph joins with one worker slot,
known spawn/handoff/publication recovery, and bounded invalid-plan failure.

The adaptive cases run a Python parent, a Python branch and Node leaves with
one worker slot. Four children are absent from the initial plan. Tests cover
cooperative joins, grandchildren's narrowed rights, worker and host death,
original spawn/send receipt recovery, initialization-pinned receipt
verification, cycle rejection, conflicting submissions, forged parent input,
unknown or broader templates, shared quotas, cancellation and template drift.
The process crate separately kills a host immediately after child commit and
checks that the unknown kernel operation is denied without creating another
child. These checks establish local execution behavior; they do not measure
model quality, independent adoption or OS isolation.
