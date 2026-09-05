# Host agent processes with existing MCP tools

`chio process` runs the Rust process runtime as a local host. Python and
JavaScript applications connect through the authenticated worker protocol;
tool execution uses existing MCP subprocesses, native mailbox tools, native
Chio policy and the durable kernel admission journal. No Rust application
code is required.

This is an experimental Unix deployment profile with one active host per
state directory and an initial process tree declared at initialization. On Linux,
[`chio process run`](PROCESS_RUNNER.md) also launches a worker application
with bounded concurrency, dependencies and persistent restart attempts.
An optional [adaptive profile](PROCESS_RUNNER.md#adaptive-child-work) lets
workers create narrower children from operator-defined templates through
kernel tools. `serve` remains available for externally managed workers; it
keeps adaptive tools disabled. Neither command
installs a worker sandbox.

The [packaged Python and Node starter](../../../examples/process-starter/README.md)
builds an offline application kit with this host and both installed SDKs.
It demonstrates scoped mailbox communication, automatic worker recovery and
independent receipt verification outside the repository checkout.

## Configure and initialize

Build the CLI from this checkout:

```bash
cargo build --locked -p chio-cli --bin chio
```

Create a policy with concrete grants or whole-name `*` grants. All root grants
must use one TTL group. Children select concrete tools from their parent's
scope; constraints and invocation budgets remain on those grants. Parents
need the `delegate` operation to authorize children.

```yaml
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 8
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: reports
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
```

Save the following as `host-config.json` beside `policy.yaml`. Replace the
command with the absolute executable and literal arguments for your existing
MCP server. No shell interprets this command. The server must advertise the
configured `read` and `publish` tools.

```json
{
  "schema": "chio.process.host.v1",
  "policy": "policy.yaml",
  "servers": [
    {
      "id": "reports",
      "command": ["/absolute/path/to/python", "/absolute/path/to/report_server.py"]
    }
  ],
  "limits": {"max_processes": 4, "max_depth": 2, "max_calls": 100},
  "children": [
    {
      "id": "researcher",
      "parent": "root",
      "tools": [{"server_id": "reports", "tool_name": "read"}],
      "budget_share_bps": 3000
    },
    {
      "id": "editor",
      "parent": "root",
      "tools": [
        {"server_id": "reports", "tool_name": "read"},
        {"server_id": "reports", "tool_name": "publish"}
      ],
      "budget_share_bps": 3000
    },
    {
      "id": "publisher",
      "parent": "editor",
      "tools": [{"server_id": "reports", "tool_name": "publish"}],
      "budget_share_bps": 1000
    }
  ]
}
```

Parents precede children. The automatically created `root` has the policy's
default scope. Child and grandchild capabilities carry the original signed
ancestor evidence and are checked by the process runtime and kernel. Budget
shares are basis points of the root allocation; a child's share cannot exceed
its parent's, and sibling shares cannot overallocate their parent. Cancelled
processes retain their shares and consume their process slots.

```bash
target/debug/chio process init --config host-config.json --state ./host-state
mkdir -m 700 worker-sockets worker-connections
target/debug/chio process credential --state ./host-state --process publisher \
  --socket ./worker-sockets/host.sock --out ./worker-connections/publisher.json
target/debug/chio process serve --state ./host-state --socket ./worker-sockets/host.sock
```

Initialization requires an empty private directory. It creates random signing
keys, qualified durable admission state, receipts and process identities. It
queries MCP tool definitions and binds those definitions and the policy hashes
to the host record. An interrupted or failed initialization does not produce
a serving host; preserve any partial state for diagnosis and initialize a new
empty directory. Existing state is never overwritten by `init`.

The state and descriptor directories require mode `0700`, and connection files
are created with mode `0600`. The CLI never prints the bearer credential. A
connection descriptor contains that worker's credential, socket path, expiry,
kernel public key and configured tool definitions. It contains no capability
token or host signing key. Protect it as a secret.

## Configure worker mailboxes

Add `"mailboxes": [{"id": "reviews"}]` to a new host configuration to expose
`send_reviews`, `receive_reviews` and `ack_reviews` on native server `chio-ipc`.
Grant those tools in policy with the usual `invoke` and `delegate` operations,
then select each child's concrete routes. A producer can have only send
authority, while a consumer can receive and acknowledge. The reserved
`chio-ipc` server ID cannot also name an MCP server when mailboxes are enabled.
A mailbox-only host may omit `servers`.

Channels, quotas and native tool definitions are pinned at initialization.
The private `mailboxes.db` belongs to the same qualified authority and signing
key as the rest of the host. Preserve the complete state directory on recovery.
See the [mailbox contract](../../kernel/chio-process/MAILBOXES.md) for limits,
message-key deduplication, polling identities, acknowledgement rights and
uncertain outcomes. The existing worker `invoke` method handles all operations.

## Connect an application

Use the process client from the checkout (`PYTHONPATH=sdks/python/chio-process/src`)
or install the local package. Deliver the descriptor privately to its worker.

```python
import json
from chio_process import ProcessClient

with open("worker-connections/publisher.json") as source:
    connection = json.load(source)
client = ProcessClient(connection["socket_path"], connection["credential"])
result = client.invoke("publish-report-42", "reports", "publish", {"report": report})
```

For LangGraph, construct the existing process node directly from the descriptor:

```python
from chio_langgraph import ChioProcessToolNode, ProcessTool

tools = ChioProcessToolNode(client, [ProcessTool(**tool) for tool in connection["tools"]],
                           namespace="research-workflow-v1")
model_with_tools = model.bind_tools(tools.model_schemas())
builder.add_node("tools", tools)
```

Keep the connection and client outside graph state, model messages and tracing
configuration. Retain the graph's persistent checkpointer, original thread id,
assistant message ids and tool-call ids. See the
[LangGraph recovery contract](../../../sdks/python/chio-langgraph/README.md).
The Node client accepts the same descriptor's `socket_path` and `credential`.
SDKs preserve signed receipt text; independent signature verification remains
the consumer's responsibility.

The [repository review application](../../../examples/repository-review/README.md)
runs concurrent readers and a publisher through this host. It also exports
original receipts for `chio receipt verify --input receipts.ndjson
--trusted-kernel-pubkey kernel.pub`, which checks signatures and action hashes
without requiring a live service or claiming policy replay.

## Recovery and administration

`chio process status --state ./host-state` reads the latest native runner
snapshot while the host is live or stopped. `chio process logs --state
./host-state --process publisher --attempt 1` reads that attempt's retained
stdout/stderr. These local diagnostics do not open a kernel or reconcile
admissions. See the [runner diagnostic contract](PROCESS_RUNNER.md#persistence-and-operating-boundary)
for stale observations, lock sampling and private log handling.

SIGINT and SIGTERM stop acceptance and drain admitted calls before removing
the host's own socket. After abrupt host death, choose a fresh socket path;
the host never deletes an existing path to make startup succeed. Stop the host
before issuing a new connection descriptor with the new socket path. Keep the
same state directory, process id and logical operation keys when recovering.
Credential rotation preserves operation identity.

Successful durable operations recover their original signed receipts and
outputs. If the host dies after an external effect but before recording its
outcome, recovery remains incomplete and does not authorize redispatch.
Starting a new host state directory or generating a new operation key creates
a new operation and cannot be used as a safe retry of an uncertain effect.

Administrative operations acquire the same exclusive lock as serving. This
prevents a second kernel from reconciling a live host's calls. While stopped:

```bash
target/debug/chio process revoke --state ./host-state --process publisher
target/debug/chio process cancel --state ./host-state --process editor
```

Revocation removes all bearer credentials for the exact process. Cancellation
permanently stops admissions and withholds outputs for the process subtree.
Neither operation undoes external effects. A new credential cannot extend the
underlying capability's expiry or restore a cancelled process. This profile
does not renew expired capabilities or rebind existing process identities.

The host rejects changed policy hashes or MCP tool definitions on restart.
These checks bind declared configuration, not executable bytes or external
service state. Operators remain responsible for deployed code identity and
compatible service behavior. Global CLI store and control URL overrides are
rejected; all persistence belongs to the selected host state directory.

## Execution boundary and verification

Keep signing keys, databases, tool credentials and other workers' descriptors
outside each worker's OS isolation boundary. Expose only its own connection
descriptor and the worker socket. Ordinary same-user processes can read each
other's private files; the protocol does not establish OS isolation. MCP
servers also require host-managed isolation and least privilege.

The worker protocol exposes tool invocation, inspection, checkpoints and
subtree cancellation. It does not carry DPoP, governed authorization or human
approval responses. Kernel policies requiring those inputs still deny calls.
Nested sampling, resource and prompt operations and distributed migration are
outside this host profile. The Linux runner supplies local direct-worker
lifecycle and dependency scheduling. Adaptive children select from the pinned
run plan's templates and retain the same process-tree and admission bounds.

The integration test uses a real CLI process, an MCP subprocess and the Python
worker client. It covers narrowed grandchild execution, denied publication,
abrupt host death, credential rotation, original receipt recovery, exclusive
administration, revocation, cancellation, a shared call ceiling and
policy/tool-definition drift. Recovery of completed calls remains possible
after that ceiling is exhausted.

```bash
cargo test --locked -p chio-cli --test process_host
```
