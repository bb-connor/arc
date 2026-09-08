# Shared-resource swarm baseline

This directory supplies the application-owned resource for the
[swarm execution experiment](../../docs/architecture/SWARM_EXECUTION_CONTRACT.md).
It is a runnable MCP service with durable operation outcomes and conditional
document replacement. Both a framework-only application and a Chio-mediated
application can use the same service. The LangGraph workload runner is wired
for live OpenAI calls and the public Chio process host. Local checks have run
its baseline graph with scripted responses; the live run and full native host
qualification remain pending. The AI SDK workload runner is not implemented yet.

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
`task`, `snapshot`, `replace`, and `outcome`. `replace` requires a document ID, its
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
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"snapshot","arguments":{"document":"release-board"},"_meta":{"chioRequestId":"saved-thread/read-call-1"}}}
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
python3 -m unittest discover -s examples/shared-resource-swarm -p test_resource.py -v
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

## Run the live LangGraph comparison

Install the existing locked framework profile from the repository root:

```sh
uv sync --project sdks/python/chio-langgraph --locked --extra dev --extra process
```

Configure `OPENROUTER_API_KEY` in the worker environment and choose an available
tool-calling model, including its organization prefix, in `CHIO_SWARM_MODEL`.
The key stays out of bootstrap documents, model prompts, and retained evidence.
The example uses OpenRouter's documented [chat-completions endpoint](https://openrouter.ai/docs/api_reference/overview)
and requests [parameter support with provider fallbacks disabled](https://openrouter.ai/docs/guides/routing/provider-selection).
The client disables automatic provider retries. Each of two workers is
bounded to eight model calls and 2048 completion tokens per call. The calls
incur the selected provider's ordinary charges.

```sh
SWARM_RUNS=$(mktemp -d "${TMPDIR:-/tmp}/cs.XXXXXX")
sdks/python/chio-langgraph/.venv/bin/python examples/shared-resource-swarm/run.py \
  --backend baseline --provider openrouter --model "$CHIO_SWARM_MODEL" \
  --output "$SWARM_RUNS/baseline"
sdks/python/chio-langgraph/.venv/bin/python examples/shared-resource-swarm/run.py \
  --backend chio --chio target/debug/chio --provider openrouter --model "$CHIO_SWARM_MODEL" \
  --output "$SWARM_RUNS/chio"
```

Both commands require a new output directory. They use identical task inputs,
model settings, worker assignments, tool schemas and versioned resources.
Direct OpenAI access remains available with `--provider openai` and
`OPENAI_API_KEY`. Provider selection is retained in the worker input binding,
model journal, and report; it cannot change during recovery. OpenRouter calls
are recorded as `live_openrouter`, direct OpenAI as `live_openai`, and scripted
checks as `scripted_test`. Reports require the selected provider's evidence kind.
The Chio case provisions signed native demo launch policy and uses `process
serve` with externally managed workers. Its demo launch policy supplies no OS
containment. It does not need the Linux-only native worker runner. Run it with
trusted application code and preserve the private state directory.
The directory's ancestors must not be group or world writable unless sticky.
This development machine's `/private/tmp` lacks the sticky bit; its protected
per-user `TMPDIR` is suitable. Do not relax the directory checks to run a test.

`provider.py` commits an in-flight model record before sending a request and
the complete response before releasing tool calls to the graph. An incomplete
provider record stops automatic recovery. LangGraph's `SqliteSaver` persists
graph transitions synchronously; the Chio backend uses `ChioProcessToolNode`.
The baseline's application MCP bridge retains its own stable tool identities
from the same persisted graph. It does not use Chio's tool execution or kernel
journal. The resource's deduplication and version checks apply to both cases.

`report.json` records resource mutations, original provider responses and usage,
worker outcomes, and mechanical task acceptance. The Chio case exports original
receipts and verifies them using the initialized kernel key. A finished graph
alone is not acceptance: the board must contain all three correct decisions
with the decisive evidence IDs, both workers must finish, and recorded inference
must be live. The checker does not grade the quality of free-form explanations
or establish production usefulness. Identical inputs do not make live model
responses identical; repeated runs remain necessary for outcome comparisons.

`langgraph_worker.py` can resume with the same private stdin bootstrap, existing
graph/model journals and thread identity. Keep settings unchanged; supply a
new host-issued connection if the native host socket or credential rotates.
The top-level `run.py` currently initializes fresh comparisons only. It does
not yet orchestrate worker failover, replace mailbox holders or resume an
interrupted whole comparison.

Run all local checks with an installed LangGraph environment:

```sh
sdks/python/chio-langgraph/.venv/bin/python -m unittest discover \
  -s examples/shared-resource-swarm -v
```

Eighteen checks cover the resource, saved provider-response identity, unknown
provider outcomes, real MCP graph execution, checkpoint-gap replay and acceptance
negative controls. Local graph checks use installed LangGraph 0.6.11 and an
in-memory checkpointer retained across graph reconstruction. They do not prove
OS worker recovery with `SqliteSaver`. All provider responses in those tests
are explicitly scripted. The process-workers workflow schedules the checks
on the locked and compatibility profiles; hosted results are still required.

`qualify_native.py --chio /path/to/chio --output /path/to/new/private-directory`
exercises the Chio graph with scripted provider responses, abruptly kills the
real host after a committed update, then starts a new host with a fresh socket
and rotated credential. It requires the original receipt to recover and verify,
with one resource mutation and one delivery. The test driver retains its
in-memory graph checkpoint; this does not establish OS graph-worker recovery.
The Linux workflow runs this qualification without provider credentials and
exports only its nonsecret report, receipt and kernel public key.

Locally, provisioning and initialization succeeded after using a protected
temporary directory. Host serving then failed with `Operation not permitted`
before readiness, so the native qualification is not yet established here.
