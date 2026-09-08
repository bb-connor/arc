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
It is not a signed credential or a mailbox ownership proof. Without an explicit
resource assignment, an old worker with an ordinary valid tool grant can read
the latest version and perform a new update. The handoff experiment below
reproduces that boundary and exercises the assignment check.

## Resource checks and evidence

```sh
python3 -m unittest discover -s examples/shared-resource-swarm -p test_resource.py -v
```

Run that command from the repository root. The nine tests use real server
subprocesses and SQLite state. They cover discovery, task input identity,
concurrent conditional writers, changed-request refusal, malformed requests,
stable reads and polls, transport attempt changes, and process death after a
committed effect before response delivery. No test invokes a model.

The [execution record](../../docs/architecture/SWARM_EXECUTION_CONTRACT.md)
links retained live comparisons, worker-death recovery, and ownership handoffs
through installed LangGraph and AI SDK integrations. It separates task
acceptance, superseded-worker mutations, original receipt recovery and model
responses from scripted checks. A correctly implemented baseline uses the same
resource protections. Broader adoption value and reduced integration effort
remain separate from these controlled synthetic workloads.

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

The common instructions and tool definitions live in `contract.py`. The board's
document ID and output shape are explicit. The generic document resource still
accepts arbitrary JSON objects; task correctness is checked separately. Initial
live runs with ambiguous instructions failed in both backends and are not counted
as evidence of a kernel coordination defect.
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

## Run the AI SDK integration

Install the TypeScript workspace dependencies first with `npm ci --ignore-scripts`
in `sdks/typescript`. From the repository root, create an installed consumer using
one of the existing pinned profiles. This packs the real process packages, checks
the dependency lock and installs from that lock:

```sh
python3 examples/shared-resource-swarm/install_ai_sdk.py \
  --profile ai7 --output "$SWARM_RUNS/sdk"
sdks/python/chio-langgraph/.venv/bin/python examples/shared-resource-swarm/run.py \
  --framework ai-sdk --consumer "$SWARM_RUNS/sdk/ai7" \
  --backend chio --chio target/debug/chio --provider openrouter \
  --model "$CHIO_SWARM_MODEL" --output "$SWARM_RUNS/ai-sdk"
```

`--profile ai6` installs the other supported profile. The application uses
`ChioProcessAgent` for native model-response journaling and tool execution.
It shares the task, instructions and resource definitions with LangGraph and
exports original provider responses and receipts. The baseline comparison uses
LangGraph; this additional integration does not implement an AI SDK-only baseline.
The consumer directory receives a copy of the worker application, whose source
hash and model configuration are bound to its saved turn.

## Compare worker recovery

Add `--scenario worker-after-effect` to either LangGraph command or the AI SDK
command. The performance worker exits with status 77 immediately after receiving
a committed replacement, before its framework can finish recording the tool step.
The driver waits for that process to exit and permits one restart with the same
input and journals. The other worker receives no injected failure.

The report requires the recorded exit sequence `[77, 0]` and the fault marker as
well as normal task acceptance and, for Chio, verified receipts. Inspect the
resource operation's delivery count and original receipt identity. The direct
MCP baseline retains its own durable model and graph state plus resource-side
deduplication; it is not a disposable-callback baseline. This scenario exercises
worker process death while the host and resource remain available. Host death
is covered separately by the scripted native qualifier.
The top-level `run.py` initializes a fresh comparison and can restart the worker
after the injected exit-77 failure. Resuming an interrupted whole comparison
and general service failover are not implemented.

Run all local checks with an installed LangGraph environment:

```sh
sdks/python/chio-langgraph/.venv/bin/python -m unittest discover \
  -s examples/shared-resource-swarm -v
```

The checks cover resource transactions, operator assignment, saved provider
identities, unknown outcomes, real MCP graph execution, checkpoint-gap replay
and acceptance controls. Their model responses are scripted and their graph
checkpointer remains in the test driver. The separate live worker-death runs
use `SqliteSaver` or the AI SDK's native journal. The process-workers workflow
schedules the application checks on locked and compatibility profiles; the
execution record and PR distinguish local results from hosted acceptance.

`qualify_native.py --chio /path/to/chio --output /path/to/new/private-directory`
exercises the Chio graph with scripted provider responses, abruptly kills the
real host after a committed update, then starts a new host with a fresh socket
and rotated credential. It requires the original receipt to recover and verify,
with one resource mutation and one delivery. The test driver retains its
in-memory graph checkpoint; this does not establish OS graph-worker recovery.
The Linux workflow runs this qualification without provider credentials and
exports only its nonsecret report, receipt and kernel public key.

Native host recovery and receipt verification have passed locally. The
execution record pins their source commits, binaries and exported evidence.

## Live task handoff

`handoff.py` pauses the superseded worker after its first task read. The operator
publishes corrected, versioned evidence, starts a replacement, waits for its
accepted assessment, and releases the old worker. Both use the same model,
instructions, document CAS and operation journal. The original seed and all task
revisions are retained. Only the operator can publish a revision; the worker MCP
interface has no such operation. A repeated logical task read still returns its
original revision.

Use the same environment and installed consumers as the live runs above:

```sh
sdks/python/chio-langgraph/.venv/bin/python examples/shared-resource-swarm/handoff.py \
  --backend baseline --provider openrouter --model openai/gpt-4.1-mini \
  --output "$SWARM_RUNS/handoff-baseline"
sdks/python/chio-langgraph/.venv/bin/python examples/shared-resource-swarm/handoff.py \
  --backend chio --provider openrouter --model openai/gpt-4.1-mini \
  --chio "$SWARM_RUNS/chio" --output "$SWARM_RUNS/handoff-chio"
```

For the installed AI SDK integration, add `--framework ai-sdk --consumer /path/to/ai7`
to the Chio command. The operator keeps the old worker's capability valid: this
measures whether scheduling a replacement and using document versions alone
protect the new result. It does not simulate capability revocation or claim that
the old worker is unauthorized under the existing contract.

`handoff.json` separates scenario completion, replacement acceptance, final task
acceptance and mutations after releasing the old worker. Exit zero means the
measurement completed; inspect `final_task_accepted` for the workload outcome.
`report.json` retains provider responses, resource operations and receipt status.
The barrier times out and the driver terminates its workers if the scenario cannot
complete. The fixture database schema is now 3; use fresh run directories. No
automatic migration or reinterpretation of earlier experiment state occurs.

Add `--ownership resource` to run the same handoff with an explicit resource
assignment. The operator assigns the document to the old caller before work
starts. At handoff, one SQLite transaction publishes the corrected task revision
and assigns the document to the replacement. Each new write checks that owner
inside its mutation transaction. A superseded caller receives a known
`superseded` result and stops; its old successful operation can still replay its
original outcome without another mutation. Uncertain outcomes retain the existing
recovery rules.

For Chio ownership runs, the operator invokes `board-admin.assign` through the
same installed `chio_process.invocation` helper used by the PostgreSQL example.
The child capabilities exclude this server. Assignment and the optional task
revision commit in one SQLite transaction together with the caller-bound
operation outcome. Replaying an old assignment returns its original result;
it cannot move ownership back. Known generation or task-revision conflicts are
retained outcomes with no partial publication. The competent direct-MCP
baseline continues to use its own local operator API for the same transition.

Each Chio handoff records and verifies two operator receipts alongside the
worker receipts. `operator_assignment_calls` must be two for the owned Chio
scenario to complete. The native ownership qualifier also verifies operator
receipt recovery after a host restart, refusal of a child assignment call,
recovery through `python -m chio_process.invocation`, and rejection of a wrong
trusted verification key. Inspecting an assignment is an observation; it does
not authorize retry of an uncertain effect under a new operation identity.

The Chio path receives `chioCallerCapabilitySha256` in MCP `_meta` from the
kernel-owned stdio pipe. The CLI's private connection descriptor supplies the
same public digest as `caller_capability_sha256`, so the operator can assign work
without reading the process database or exposing a capability token. It binds
the exact signed capability, including its scope and delegation. Issuing a new
capability requires an explicit assignment change; rotating a worker connection
credential for the same capability preserves the binding. The digest is not a
credential or a signed assertion. A resource must trust its private connection
to the kernel before authorizing from this metadata; an arbitrary HTTP caller's
copy would have no authority.

The competent baseline binds an application-selected identity to each private
MCP subprocess using `--connection-caller`. It uses the same assignment table and
atomic write check. Its trusted application selects the connection identity;
Chio supplies the validated capability binding through the shared adapter.
These externally managed native processes measure the tool-call boundary and
recovery. They do not establish OS isolation against arbitrary code running as
the same local user. Both integrations should preserve the revised assessment
with this resource contract. This is a
test of reusable enforcement and integration, not a claim that the baseline
cannot implement ownership.

Run the deterministic native controls with the rebuilt CLI:

```sh
sdks/python/chio-langgraph/.venv/bin/python examples/shared-resource-swarm/qualify_ownership.py \
  --chio "$SWARM_RUNS/chio" --output "$SWARM_RUNS/ownership-qualification"
sdks/python/chio-langgraph/.venv/bin/python examples/shared-resource-swarm/qualify_native.py \
  --resource-ownership --chio "$SWARM_RUNS/chio" --output "$SWARM_RUNS/owned-host-recovery"
```

These checks cover fresh-version writes by a superseded caller, model argument
spoofing, missing caller metadata, exact receipt replay, and host death with
credential rotation. They do not constitute live-model evidence.
