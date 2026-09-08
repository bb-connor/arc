# Shared-resource swarm baseline

This directory supplies the application-owned resource for the
[swarm execution experiment](../../docs/architecture/SWARM_EXECUTION_CONTRACT.md).
It is a runnable MCP service with durable operation outcomes and conditional
document replacement. Both a framework-only application and a Chio-mediated
application can use the same service. Live LangGraph and AI SDK workload runners
are not implemented here yet.

The first task fixture is a synthetic release-readiness board. Workers assess
candidate-specific evidence for three services and update a shared document
without discarding each other's assessments. No command deploys anything or
contacts real infrastructure. The fixture's small size makes it an initial
integration check; it cannot establish production workload value.

## Run the resource

Python 3.11+ is sufficient. From this directory, choose a fresh private state
directory and initialize it once:

```sh
mkdir -m 700 /tmp/chio-shared-resource-example
python3 server.py --database /tmp/chio-shared-resource-example/resource.db \
  --initialize seed.json
python3 server.py --database /tmp/chio-shared-resource-example/resource.db
```

The server speaks newline-delimited MCP JSON-RPC on stdin/stdout. It advertises
`task`, `read`, `replace`, and `outcome`. `replace` requires a document ID, its
expected integer version, and a complete JSON object. A mismatched version
returns a known `version_conflict` without changing the document. The resource
does not evaluate whether a release assessment is correct.

The MCP client must supply a stable operation identity in
`params._meta.chioRequestId`. Chio's existing MCP adapter supplies this from
its kernel dispatch context. A baseline application must supply it from its
persisted model/tool-call identity before sending an effectful request. JSON-RPC
request numbers and OS attempt numbers are not durable operation identities.
Do not expose identity selection as a model tool argument.

For example, this request reads the initial document:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{"document":"release-board"},"_meta":{"chioRequestId":"saved-thread/read-call-1"}}}
```

For Chio host configuration, use server ID `board` and the absolute command
`[python_executable, server_script, "--database", database_path]`. Provision
its signed native launch policy through the existing
[process host](../../crates/products/chio-cli/PROCESS_HOST.md) procedure. Scope
workers to the required concrete tool routes. This directory does not provide
or replace the host's authority, worker credentials, or isolation profile.

Inspect a consistent resource snapshot separately:

```sh
python3 server.py --database /tmp/chio-shared-resource-example/resource.db --inspect
```

The output includes the immutable input digest, document versions and contents,
bound requests, saved results, delivery counts and committed mutations. Keep
the database, its WAL files, and the application journals together across
restart. Initialization refuses an existing file; serving missing state does
not create a replacement database.

## Recovery contract

The resource commits a conditional document update and its operation outcome
in one SQLite transaction. Repeating the same operation returns its original
result. Changing the tool or arguments under that identity is refused. The
resource continues to deduplicate after its process dies and restarts.

Reads and outcome lookups also have stable results. A replayed read returns
its original snapshot. Use a new logical read or poll to observe newer state.
A known version conflict can lead to a new read and newly planned operation;
it must not be confused with an uncertain external effect. An outcome lookup
returns both the original bound request and its result so a caller can compare
them before accepting the outcome. An `unknown` lookup does not itself grant
redispatch authority.

This resource-level lookup does not automatically complete an uncertain Chio
kernel admission. The kernel's existing uncertainty contract still applies.
Do not invent a new Chio operation identity to work around an incomplete call.

Metadata is trusted only through the operator-controlled stdin connection.
It is not a signed credential or a mailbox ownership proof. The resource
does not fence job owners: an old worker with an ordinary valid tool grant
can read the latest version and perform a new update. That is the measured
boundary the next workload must evaluate.

## Checks and remaining experiment

```sh
python3 -m unittest discover -s examples/shared-resource-swarm -v
```

Run that command from the repository root. The nine tests use real server
subprocesses and SQLite state. They cover discovery, task input identity,
concurrent conditional writers, changed-request refusal, malformed requests,
stable reads and polls, transport attempt changes, and process death after a
committed effect before response delivery. No test invokes a model.

The live experiment still needs both installed framework adapters, retained
provider responses before effects, receipt verification through Chio, bounded
failover scheduling and a framework-only comparison with the same resource
protections. Measure accepted task outputs, writes from superseded workers,
duplicate effects, discarded assessments, interventions, model usage, wall
time and the application code needed for recovery. A forced ownership race
alone cannot establish that a new capability improves useful task completion.

Do not count these local resource checks as that live comparison or as two
independent application integrations.
