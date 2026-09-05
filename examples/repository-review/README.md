# Restartable repository review

Analyze a Git change set with two separate reader processes, hand their
results through Chio mailboxes, and publish one local report through a
separately authorized worker.
The application uses `chio process`, the Python process client and LangGraph.
It contains no Rust bootstrap code and does not bypass the host to run tools.

For a coordinator that chooses and spawns reviewer processes after inspecting
the change set, use the [adaptive application](ADAPTIVE.md). It supports
model-selected assignments, native child joins and recovery with one worker
slot.

The default mode produces a deterministic change inventory. A model factory
enables independent code and test review agents with the same tools and
recovery path. The qualification suite uses an explicitly scripted model;
live model quality and external application adoption remain unverified.

## Run on a repository

From the Chio checkout, install the locked application dependencies and build
the host. Python 3.11+ and a Unix host are required.

```bash
uv sync --project sdks/python/chio-langgraph --locked --extra process --extra dev
cargo build --locked -p chio-cli --bin chio

sdks/python/chio-langgraph/.venv/bin/python examples/repository-review/review.py prepare \
  --repo /path/to/repository --base HEAD~1 --head HEAD \
  --run-dir /tmp/my-review --chio "$PWD/target/debug/chio"
sdks/python/chio-langgraph/.venv/bin/python examples/repository-review/review.py run \
  --run-dir /tmp/my-review
```

Use a new, short run-directory path whose parent already exists. `prepare`
creates an owner-only directory and never overwrites a prior run. The native
host also checks the security of its parent directories. A failed preparation
may leave diagnostic state; preserve it and use a new directory. The run is
ready only after `run.json` exists.

The final command prints paths to `report.md` and `evidence.json`. Evidence
contains the original signed receipt text, pinned commit and snapshot
identities, three worker PIDs, publication count and measured setup/recovery
time. It contains no worker credential. Report history lives in
`publications.db`; exported Markdown and JSON can be regenerated.

On Linux, let the native host own worker lifecycle and automatic restarts:

```bash
sdks/python/chio-langgraph/.venv/bin/python examples/repository-review/review.py run-native \
  --run-dir /tmp/my-review
```

Choose a launch mode for a freshly prepared run and retain it across recovery.
`prepare` writes `worker-plan.json`: concurrent readers precede the publisher,
each with three persistent attempts and a ten-minute attempt deadline. The
wrapper calls `chio process run`, then verifies the existing receipt exports.
The native runner delivers credentials over stdin, rotates them between
attempts, and preserves the application's graph and operation identities.
It owns dependency scheduling and direct worker termination. See the
[runner contract](../../crates/products/chio-cli/PROCESS_RUNNER.md) for Linux
process boundaries, exhausted attempts and uncertain outcomes.

The default inventory lists changed code and test paths with before/after
line counts. Test detection is a path-name heuristic. It does not execute
tests, find semantic defects or establish coverage. Binary files, symlinks,
submodules and text over 64 KiB have explicit omission reasons. Runs accept
1-128 changed paths and at most 8 MiB of captured source. No uncommitted
working-tree content is read, and repository code is never executed.
Git replacement refs and ambient `GIT_*` repository overrides are disabled
during capture. The source digest binds the actual captured content.

## Use a model

Provide an importable `module:factory` that accepts the role (`changes` or
`tests`) and returns your configured LangChain chat model. The worker uses
the model's [tool binding and invocation interface](https://docs.langchain.com/oss/python/langchain/models).
Install your chosen provider integration in the same environment. For example,
an application's existing model setup can be exposed without changing its
provider selection:

```python
# review_model.py, in your application's import path
from my_application.models import review_chat_model

def create(role):
    return review_chat_model(role=role)
```

Prepare a new run with `--model-factory review_model:create` and make that
module available through the worker's Python import path. Supply provider
credentials through your existing private environment. The factory is
trusted application code. Do not put credentials in messages or graph state.
Using a remote provider sends the source selected by its tools to that provider.

Each reader gets its inventory tool and `read_file`. The model chooses which
changed files and revisions to read, then returns a Markdown review. A reader
reviewing tests also receives the other changed paths, so it can inspect code
changes even when no test file changed. Each reader
cannot finish without consulting at least one tool. Findings require human
verification; prompts and signed tool receipts do not prove model correctness.
After review, each reader graph sends its result to its own mailbox. The
model receives only repository-read tool schemas. The publisher receives both
handoffs, composes the report, publishes it, and acknowledges both messages.
Its capability grants publication plus receive/acknowledgement on those two
channels. It does not call a model.

`--max-rounds` defaults to eight persisted model turns per reader. The shared
`--max-calls` ceiling defaults to 100 mediated tool operations. A worker group
has a ten-minute wall deadline. These are not provider token or monetary
budgets: model API calls happen in application planning nodes outside Chio.
Set provider limits separately. Denials, MCP errors, transport failures and
incomplete operations stop the graph instead of generating a new retry key.

## Resume and verify

Run the same `run` command to resume. Reader checkpoints and pending publisher
tool calls retain their original identities. The coordinator issues new
credentials, chooses a fresh socket and reopens the same host state. It
revokes the previous credentials for those workers before serving. The source
snapshot and application file hashes must match the prepared run.

LangGraph retains planning through its
[persistent checkpointer](https://docs.langchain.com/oss/python/langgraph/persistence).
The Chio journal retains mediated operation identity and known outcomes.
Changing the run directory, graph databases, thread identity or operation keys
is a new run, not recovery. Preserve the full private directory. Capabilities
expire after one hour in this profile and cannot currently be renewed.

To exercise handoff and publication checkpoint failures:

```bash
# Expected to fail after one reader sends, before its graph checkpoint.
sdks/python/chio-langgraph/.venv/bin/python examples/repository-review/review.py run \
  --run-dir /tmp/my-review --crash-after-handoff changes

# Recover that handoff, then fail after publication, before its graph checkpoint.
sdks/python/chio-langgraph/.venv/bin/python examples/repository-review/review.py run \
  --run-dir /tmp/my-review --crash-after-publication

# Same state, fresh workers and host; the completed publication is recovered.
sdks/python/chio-langgraph/.venv/bin/python examples/repository-review/review.py run \
  --run-dir /tmp/my-review
```

Use these fault flags on a freshly prepared run; completed graph nodes have no
pending operation to interrupt. The handoff flag exits a reader after send
returns; the publication flag exits the publisher and then kills the host.
A host failure after an effect but before its
durable outcome is recorded remains uncertain and blocks redispatch. The
report tool appends publication history without its own idempotency key;
this test targets the recorded-outcome recovery boundary.

The application verifies every exported receipt before reporting completion:

```bash
target/debug/chio --json receipt verify --input /tmp/my-review/receipts.ndjson \
  --trusted-kernel-pubkey /tmp/my-review/kernel.pub
```

This command verifies signatures, the explicitly pinned signer and canonical
action parameter hashes. Input is NDJSON with strict I-JSON parsing, at most
8 MiB per line, 64 MiB total and 10,000 receipts. An empty input, malformed
line or failed receipt fails the whole command. Unsupported fields outside
the current signed receipt schema are rejected. Obtain the public key from
the trusted host setup; accepting a key from an untrusted evidence package
does not establish signer trust. The command does not re-evaluate policy,
prove log inclusion/completeness, or validate arbitrary tool output. The
application additionally checks that its report and snapshot hash match the
publisher's signed invocation parameters.
The publication tool returns a numeric record ID. Integrity hashes are derived
locally after verification: the native output sanitizer can mask digit runs
inside hexadecimal hashes, so model-visible tool output is not an immutable
channel for those hashes.

## Qualification and operating boundary

```bash
sdks/python/chio-langgraph/.venv/bin/python -m pytest -q \
  examples/repository-review/test_snapshot.py
sdks/python/chio-langgraph/.venv/bin/python examples/repository-review/qualify.py \
  --chio "$PWD/target/debug/chio" --output target/repository-review
sdks/python/chio-langgraph/.venv/bin/python examples/repository-review/qualify_native.py \
  --chio "$PWD/target/debug/chio" --output target/repository-review-native
```

Qualification runs inventory and scripted model profiles over a real Git
fixture, executes tools in separate worker processes, exits a reader after
handoff, kills the publisher and host after publication, removes the test
oracles, and verifies recovery of original signed receipts with one publication.
Both channels contain one acknowledged message identity after recovery.
Inventory verifies nine receipts and the scripted model verifies thirteen.
It also checks unauthorized publication,
shared call-limit exhaustion, cancellation, source drift, clean repeated
resume and absence of bearer credentials in worker checkpoints/logs/results.
The pinned Git fixture also reproduces a report hash that matches the native
compact-SSN detector, covering publication verification with sanitization active.
Recorded wall times include interpreter startup and CLI administration. They
are not kernel latency measurements or a framework performance comparison.

Native qualification runs the same inventory and scripted-model graphs with
automatic restart after a reader handoff and a publication. It requires two
attempts for the interrupted reader and publisher, one for the other reader,
the original receipts, one publication, and unchanged completed-worker state
on repeat. It also checks that no connection descriptor files are needed.

The coordinator owns all private state and launches the publisher after both
reader graphs finish. Review text travels through
[kernel mailbox tools](../../crates/kernel/chio-process/MAILBOXES.md); result
files export original receipts and completion metadata. Graph joins and OS
worker lifecycle in the original `run` mode remain application responsibilities.
`run-native` delegates direct worker lifecycle and dependencies to the host.
Acknowledgement frees
pending mailbox payloads but does not erase recorded receive outputs or graph
checkpoints. Endpoint rights do not attest a claimed sender identity.
SIGINT/SIGTERM clean up worker processes and drain the host. If the coordinator
is killed abruptly, its host may remain alive; stop that host before resuming.
The exclusive host lock rejects concurrent administration. Cancellation is
available through `chio process cancel` while the host is stopped; cancelling
`editor` also cancels `publisher` and does not undo a published report.

All processes run as the same OS user in this example. The protocol scopes
tool authority, but these processes are not OS-isolated and could access each
other's files. Deploy workers in separate OS isolation boundaries before
running hostile worker code. Model output and repository text remain untrusted.
Preserve provider configuration and application dependencies across recovery;
application file hashes do not attest dependencies, executable bytes or model
service behavior. See the [host boundary](../../crates/products/chio-cli/PROCESS_HOST.md).
