# Governed process fan-out

The process host can now bind a fixed fan-out to the capabilities it actually
issues. It installs the live swarm verifier, shares one signed aggregate
invocation budget, and retains single-use continuations in the existing durable
admission authority. Native MCP tools in this profile require verified Enforced
cage launch with no network destinations. A missing prerequisite refuses startup.

This path is being qualified for M5. The existing `smoke.sh` keeps its Disabled
integration-only behavior. The commands below do not yet produce the complete M5
scenario, accounting, confinement and terminal-outcome acceptance artifact.

## Initialize

Use an ordinary process host configuration with persistent receipts and
revocations, `durable_admission_mode: all`, and
`kernel.require_swarm_admission: true`. Declare a root and fixed direct children.
Each child receives only the tools needed for its task. Native server entries
must reference signed Enforced launch policies; `security provision-reference-runtime`
is the existing provisioner. Keep its operator keys outside worker custody.
The current profile supports 2-32 children with one planned call per child.
Dynamic spawn templates and deeper graphs are refused.

A plan names real configured processes and concrete calls:

```json
{
  "schema": "chio.process.swarm-plan.v1",
  "graph_id": "repository-review",
  "calls": [
    {
      "process": "reader",
      "operation_key": "read-source",
      "server_id": "reference-reader",
      "tool_name": "read_file",
      "arguments": {"path": "README.md"}
    },
    {
      "process": "writer",
      "operation_key": "write-report",
      "server_id": "reference-writer",
      "tool_name": "write_file",
      "arguments": {"path": "/workspace/report.txt", "content": "Review started\n"}
    }
  ]
}
```

These calls fan out independently. This example does not claim that the writer
consumes the reader's output. Fan-in must use actual completed receipts.

```sh
chio process init --config host.json --state "$PWD/run-state" \
  --aggregate-invocations 2 --swarm-plan tasks.json
```

The invocation budget belongs to the root's entire delegation family. The
separate `limits.max_calls` in `host.json` bounds logical process operations,
including refusals. Set it high enough to retain the desired negative cases.

Initialization records a signed observation of completed capability provisioning,
the live graph, exact worker request contexts, and the pinned runtime profile.
It activates the sealed replay source once. It does not invent successful worker
results or future join/terminal receipts. The private state contains:

- `swarm-bootstrap.json`: signed trace of the actual issued capabilities.
- `swarm-bundle.json`: signed live graph, witnesses, routes and continuations.
- `swarm-calls.json`: exact invocation inputs to distribute to each worker.
- `swarm-profile.json`: signed host/source/route binding.
- `swarm-runtime.db`: verifier-owned evidence and sealed legacy replay markers.
- `authority.db`: the existing budget, revocation, outcome and continuation owner.

### Independent graphs sharing one family

Use `chio.process.swarm-plan.v2` when independent graphs must compete for the
same family invocation quota. It accepts `profile_id` and `graphs`; each graph
has the same `graph_id` and `calls` fields as the v1 plan above. For example,
this writes two mailbox graphs for four configured direct children:

```sh
python3 - <<'PY'
import json
from pathlib import Path

groups = [("first", ["alice", "bob"]), ("second", ["carol", "dave"])]
plan = {
    "schema": "chio.process.swarm-plan.v2",
    "profile_id": "shared-mailbox-family",
    "graphs": [
        {
            "graph_id": graph,
            "calls": [
                {
                    "process": name,
                    "operation_key": "publish",
                    "server_id": "chio-ipc",
                    "tool_name": "send_jobs",
                    "arguments": {"message_key": name, "payload": {"from": name}},
                }
                for name in children
            ],
        }
        for graph, children in groups
    ],
}
Path("shared-tasks.json").write_text(json.dumps(plan, indent=2) + "\n")
PY
chio process init --config host.json --state "$PWD/shared-state" \
  --aggregate-invocations 2 --swarm-plan shared-tasks.json
```

The host configuration must declare these four children with `send_jobs` access,
2500 basis points each, the `jobs` mailbox, and capacity for five processes.
Each graph retains its allocation checks and must fit within the signed family
maximum. Graphs do not reserve separate copies of that quota: all four calls
compete for the same two invocations in `authority.db`. Once two calls consume
it, the remaining calls receive signed budget-exhaustion denials before dispatch.
Which workers succeed depends on admission order.

There must be 2-8 graphs, 2-32 calls per graph, and at most 32 total calls.
Graph identifiers and child process names must be unique across the plan.
Initialization writes `swarm-bundles.json` containing the individual authorities,
one combined `swarm-calls.json`, and one sealed, activated runtime source. The
root and all children retain their original shared family binding.

Collect and verify each response with `receipt verify-process-response`.
The current `attest-run` completed-fanout format supports one graph whose tasks
all returned allowed results. It refuses this shared-family profile; a
multi-graph terminal artifact remains part of the unfinished M5 work.

## Run supervised workers on Linux

Install the local Python process SDK in the worker interpreter, or point
`PYTHONPATH` to `sdks/python/chio-process/src` for a source checkout. Then run:

```sh
python3 examples/reference-swarm/process-run.py \
  --chio /absolute/path/to/chio \
  --state "$PWD/run-state" --output "$PWD/run-evidence"
```

The script calls the existing `chio process run` supervisor. Each worker receives
its own authenticated connection on stdin, submits the exact governed call and
checkpoints its response. The supervisor retains bounded restart attempts and
rotates credentials. A repeated logical call goes through kernel recovery and
retains its original receipt; the worker does not assume an uncertain effect is
safe to repeat.

For isolated workers, add `--worker-image sha256:<local-image-id>`. The image must
contain this `process-worker.py` at `/opt/chio/process-worker.py`, its SDK, and
`/usr/local/bin/python3`. The existing fixed Docker profile mounts only the worker
socket, has no network, and exposes neither administrative state nor the Docker
socket to workers. Without this argument, workers run as ordinary native
processes under the host user. That native profile is for cooperative workers
and does not isolate them from the host's files.

Build the supplied worker image from the repository root using a reviewed Python
3.11+ base image pinned by digest. The base must provide `/usr/local/bin/python3`:

```sh
docker build --build-arg BASE="$PYTHON_BASE_DIGEST" \
  -f examples/reference-swarm/ProcessWorker.Dockerfile \
  -t chio-reference-process-worker .
WORKER_IMAGE=$(docker image inspect --format '{{.Id}}' chio-reference-process-worker)
python3 examples/reference-swarm/process-run.py \
  --chio /absolute/path/to/chio --state "$PWD/run-state" \
  --output "$PWD/run-evidence" --worker-image "$WORKER_IMAGE"
```

The image copies the dependency-free process SDK and this worker from the same
checkout. The runner requires the local immutable image ID and never pulls an
image during worker launch. Code lives outside `/work`, which the runner replaces
with a private temporary filesystem.

The output directory contains the runner output and a request, context, response
and independent `chio receipt verify-process-response` result for each worker.
The verifier checks the operator-pinned kernel key, signed process/capability
identity, original request, verdict and returned content. A fresh output directory
is required on every attempt. Preserve the same state, worker command and run
plan when resuming an interrupted run.

## Review real files through an Enforced reader

On the supported Linux x86_64 cage host, build the static PIE cage helper and
reference reader with the repository's confinement build recipe. Run as a
non-root operator. Keep the input directory separate from the output directory,
which contains private signing keys and administrative state. Select 2-32 UTF-8
files, at most 256 KiB each and 4 MiB together:

```sh
python3 examples/reference-swarm/process-prepare.py \
  --chio /absolute/path/to/chio \
  --cage-init /absolute/path/to/chio-cage-init \
  --max-artifact-bytes 2097152 \
  --receipt-rollback-anchor-root "$RECEIPT_ANCHOR" \
  --reader /absolute/path/to/chio-tool-repo-reader \
  --input-dir "$PWD/review-input" --file README.md --file DESIGN.md \
  --output "$PWD/review-host"
python3 examples/reference-swarm/process-run.py \
  --chio /absolute/path/to/chio --state "$PWD/review-host/state" \
  --output "$PWD/review-evidence" --worker-image "$WORKER_IMAGE"
python3 examples/reference-swarm/process-collect.py \
  --chio /absolute/path/to/chio --evidence "$PWD/review-evidence" \
  --inputs "$PWD/review-host/inputs.json" \
  --trusted-kernel-pubkey "$PWD/review-host/state/authority.db.kernel.pub" \
  --output "$PWD/repository-report.json"
```

Preparation invokes `security provision-reference-runtime` in its Enforced
stage, discovers the supplied trusted reader's tool surface, and initializes the
governed host. Initialization launches the actual confined tool and refuses a
missing prerequisite. Each worker receives one exact planned read. The native
tool has a signed read grant for the input directory and no network grant.
`--max-artifact-bytes` is an explicit operator resource bound recorded in the
signed launch policy. The example uses 2 MiB for optimized static binaries;
check the sizes of your built helper and reader before selecting it. The
provisioner refuses oversized inputs before creating state. Its default remains
1 MiB and the cage's global maximum remains 256 MiB.
`RECEIPT_ANCHOR` must name an existing operator-owned private directory on a
different filesystem snapshot domain from the receipt database. Keep this anchor
outside worker grants and preserve it across recovery. The signed policy pins
its path; the existing qualified receipt store verifies its generation. A
missing anchor or one on the database filesystem refuses Enforced launch.
Use an x86_64 worker image built from the same scripts/SDK on this host. Omitting
the image selects cooperative native workers with the filesystem limitation
described above.

The collector independently verifies every response with the explicitly
supplied operator key, checks the initialized runtime/capability/request identity,
and compares the returned bytes with the input hashes recorded before launch.
The report contains verified file sizes, line counts, hashes and request IDs.
Changed files, substituted worker identity and modified signed output refuse
collection. Preserve `inputs.json` and the key through an operator-trusted
channel; neither should be selected from an untrusted submitted evidence bundle.
This result check does not yet verify M5's complete accounting, confinement
chain or signed terminal artifact, and its output records that limit.

## Current boundary

The mailbox-only host regression exercises actual authenticated socket calls,
missing/borrowed authority refusals, real effects, SIGKILL recovery, retained
continuation custody and profile tampering. It is not a native confinement run.
The native worker orchestration and Enforced reference-tool run need Linux
qualification. The full M5 scenario matrix, signed completed fan-in, joined
accounting/confinement artifact and designated-runner acceptance remain open.
The process host still refuses manifests requiring an information-flow runtime
until that profile is installed. No Disabled fallback is provided for native
tools in this governed profile.

## Export a completed fan-out observation

After the supervised workers complete, export the retained result and verify it
using a kernel key and runtime ID copied from the operator's initialized state:

```sh
chio process attest-run --state "$PWD/run-state" \
  --plan "$PWD/run-state/reference-run-plan.json" --out "$PWD/completed-run.json"
chio process verify-run --artifact "$PWD/completed-run.json" \
  --trusted-kernel-pubkey "$PWD/run-state/authority.db.kernel.pub" \
  --runtime-id "$INITIALIZED_RUNTIME_ID" \
  --trusted-launch-policy-signer "reference-reader=$READER_LAUNCH_POLICY_SIGNER"
```

Export requires Linux, the retained completed worker journal, all successful
worker receipts, no outstanding container/socket cleanup, and the original
signed authority. It reads the existing aggregate quota and signs a completed
observation. It neither dispatches another tool call nor creates new admission
authority. The verifier binds actual capability bodies, graph/witness references,
worker request/result receipts, join parents and terminal result digests.

For native tools, use each server ID and policy signer from the operator-owned
host configuration. Repeat `--trusted-launch-policy-signer SERVER=PUBLIC_KEY`
for multiple native servers; omit it for hosts with only built-in mailboxes.
The supervised script supplies these pins from that configuration automatically.
The v2 artifact includes the original signed launch policy and the existing
enforcement and terminal receipts. The verifier checks the tool receipt's launch
reference, policy signer, manifest, executable bindings, execution identity,
matching launch attempt and observed lifetime. Export fails if its independently
anchored receipt store lacks the referenced launch or terminal record.

The budget pool in this artifact remains the original allocation authority.
`aggregate` separately records captured and reserved invocation counts from the
host's authoritative store. Verification checks this signed observation against
the issued family limit. Each completed call also carries fenced readback of its
operation-owned continuation claims. The verifier recomputes the original claim
commitment named in the signed tool receipt and matches the retained token,
prepared plan, request binding and terminal receipt. Historical evidence cannot
authorize another effect. Execution nonces and the full M5 scenario matrix remain
unverified; the report includes `m5_acceptance_complete: false`.

### Observe a denied or uncertain call

Stop the host and retain the caller's request, invocation context and response
envelope. The local qualifier writes these as `WORKER/request.json`,
`WORKER/context.json` and `WORKER/response.json`. Export one observation on Linux:

```sh
chio process attest-call --state "$PWD/run-state" \
  --request writer/request.json --context writer/context.json \
  --response writer/response.json --out "$PWD/writer-call.json"
chio process verify-call --artifact "$PWD/writer-call.json" \
  --request writer/request.json --context writer/context.json \
  --trusted-kernel-pubkey "$TRUSTED_KERNEL_PUBLIC_KEY_FILE" \
  --runtime-id "$INITIALIZED_RUNTIME_ID"
```

Keep the expected request, process/capability context, kernel key and runtime ID
independently of the submitted artifact. Verification works offline on supported
Unix hosts. It checks the signed provisioning record, worker response and the
operation's observed state. Completed calls must name their actual terminal
receipt and its original continuation claim commitment. Uncertain calls retain
their incident record. An original incomplete receipt must bind the exact
retained continuation commitment. A later recovery refusal instead binds the
signed `outcome_unknown_after_dispatch` projection; its continuation custody
comes from the exporter's signed store readback. `custody_binding` identifies
these different sources. Neither response claims a completed tool result.
Compensated calls cannot claim a dispatch commitment or a retained continuation.

Export uses the existing fenced, anchored store read APIs and keeps the private
admission request in the host. It signs only the public binding and custody
observation. It does not dispatch, retry, refund or release a continuation. The
observation may describe an ordinary denial without an admission record, but it
does not prove an external effect was absent. Task authority, aggregate usage,
confinement, physical effects and graph completion require their own evidence.
This command does not replace `verify-run` or close M5 acceptance.

### Observe all worker outcomes and family accounting

After every declared worker has finished and the host has stopped, export its
retained outcomes together:

```sh
chio process attest-outcomes --state "$PWD/run-state" \
  --plan "$PWD/run-state/reference-run-plan.json" --out "$PWD/outcomes.json"
chio process verify-outcomes --artifact "$PWD/outcomes.json" \
  --trusted-kernel-pubkey "$PWD/operator-kernel.pub" --runtime-id "$RUNTIME_ID" \
  --trusted-launch-policy-signer "repo-reader=$READER_POLICY_PUBLIC_KEY"
```

Supply one independently retained policy signer pin per referenced native server.
For a mailbox-only host, omit that option. Keep the kernel key and runtime ID
independently. Export reads each original
worker checkpoint under one stopped-host lease, verifies its retained call, and
reads captured usage from the existing family budget store. It also reads the
actual worker completion journal and the originally issued graph authorities.
Multiple graphs may share the same family. Every observed worker must occur in
exactly one graph; each retained continuation must bind that worker's issued
single-use token. The captured count must equal the observed committed calls,
including calls whose external outcome remains unknown. No reserved invocation
may remain in a finished observation.

Verification reports each `observed_operations` state. A null state means an
ordinary signed denial without a retained admission operation. Worker completion
records that the worker finished processing its response; the response can
still describe a denied or interrupted tool call. The original live graph
authority is retained without minting a successful join or graph completion.

Version 2 also includes each response's original signed launch reference, its
signed Enforced policy and any matching retained exit receipt. Verification
binds the original host configuration, signed manifest, exact policy bytes,
route and executable identity to the independently pinned policy signer. Each
`native_launches` entry says whether a terminal receipt was verified. A missing
exit remains unknown. Interrupted responses may be signed after observing the
process exit; they do not assert that the call completed inside its lifetime.

A recovery refusal's connection can be a replacement connection. Its launch
evidence does not identify the earlier external effect or establish that the
original target died. Those observations, physical effects, execution nonces
and the complete scenario matrix still require additional evidence.
`m5_acceptance_complete` remains false. Version 1 artifacts remain verifiable
with their original limits and no native policy signer options. The separate
completed-run verifier continues to require actual terminal launch receipts.

### Verify a launch when the observing host died

A recovered unknown-outcome response can refer to the replacement connection.
Use the original launch receipt retained before the host died to inspect the
earlier launch. Keep the server's policy signer, selected receipt ID and expected
executable digest separately from the submitted files:

```sh
chio receipt verify-native-start \
  --signed-policy original-native-launches/effect-probe-policy.json \
  --enforcement original-native-launches/effect-probe-receipt.ndjson \
  --server-id effect-probe \
  --trusted-policy-signer "$EFFECT_LAUNCH_POLICY_SIGNER" \
  --expected-receipt-id "$ORIGINAL_ENFORCEMENT_RECEIPT_ID" \
  --expected-target-sha256 "$PROBE_SHA256"
```

This offline command verifies the signed Enforced policy, manifest, receipt
semantics, helper and target digests, execution identity and selected launch.
Its report includes the signed process ID and trace identity. Matching that ID
to a live target and observing its death remain separate external observations.
This check supplies no terminal receipt, completed tool result, or receipt-log
inclusion proof. An unknown effect remains unknown. The completed fan-out
verifier still requires the actual matching terminal receipt.

## Revoke a task capability

Stop the serving host, then revoke the capability originally issued to a process:

```sh
chio process revoke-capability --state "$PWD/run-state" --process reader
```

This writes through the kernel's persistent revocation store. A later host
reopen preserves the revocation, and descendant capabilities also inherit the
refusal. Revocation is permanent; it does not undo an already admitted effect.
The command refuses while another host owns the state directory. The separate
`process revoke` command invalidates worker connection credentials.

## Run the local adversarial qualifiers

The qualification scripts use an explicit `enforcement-probe` Cargo example.
It attempts raw OS operations without the repository reader's own path checks.
Build it as a static Linux x86_64 executable alongside the qualified helper:

```sh
umask 022
RUSTFLAGS='-C target-feature=+crt-static -C relocation-model=pie' \
  cargo build --locked --release --target x86_64-unknown-linux-gnu \
  -p chio-reference-tools --example enforcement-probe

docker build --platform linux/amd64 \
  --build-arg BASE=python:3.11-slim@sha256:d1053354624536b044162aaab1e418bd000ea35184fb1ae098ab3166b1072e72 \
  -f examples/reference-swarm/QualificationWorker.Dockerfile \
  -t chio-process-qualification:local .
WORKER_IMAGE=$(docker image inspect --format '{{.Id}}' chio-process-qualification:local)
```

For each scenario, use a fresh output directory and an existing private receipt
anchor outside the tool's input paths. For example:

```sh
python3 examples/reference-swarm/qualify-process-filesystem.py \
  --chio /absolute/path/to/chio --cage-init /absolute/path/to/chio-cage-init \
  --probe "$PWD/target/x86_64-unknown-linux-gnu/release/examples/enforcement-probe" \
  --worker-image "$WORKER_IMAGE" --output "$PWD/filesystem-qualification" \
  --receipt-rollback-anchor-root /absolute/private/receipt-anchor
```

`qualify-process-network.py`, `qualify-process-authority.py`,
`qualify-process-revocation.py`, `qualify-process-host-crash.py` and
`qualify-process-budget.py` accept the same arguments. Run each on the
supported Linux x86_64 cage profile as a non-root operator. The scripts retain
commands, caller responses, signatures and external observations. Each reports
`m5_acceptance_complete: false`; the complete scenario artifact and final
qualification remain required. Crash and budget fixtures also retain original
native launch files for the separate offline check above.

### Run and verify the complete local matrix

With Python 3.11 or newer, the same qualified static helper, probe and repository
reader, and the immutable worker image above, run the seven scenarios serially:

```sh
python3 examples/reference-swarm/qualify-process-matrix.py run \
  --chio /absolute/path/to/chio --runtime-source "$RUNTIME_SOURCE" \
  --cage-init /absolute/path/to/chio-cage-init \
  --probe /absolute/path/to/enforcement-probe \
  --reader /absolute/path/to/chio-tool-repo-reader \
  --worker-image "$WORKER_IMAGE" --output /absolute/fresh/matrix-run \
  --receipt-rollback-anchor-root /absolute/private/fresh-matrix-anchor
```

`RUNTIME_SOURCE` is the full commit used to build the selected CLI. The command
records the executable hashes, qualification source, script hashes and worker
image, and refuses changing executables or scripts during the run. The output
directory must be new. The existing private anchor must have no scenario
subdirectories from another run. Existing scenario limits and assertions apply.

The resulting `matrix.json` contains all seven signed worker-outcome artifacts,
the successful graph-completion artifacts, eight original authority denials,
six original pre-crash launch records, input hashes and external observations.
Keep `operator-pins.json` separately through a trusted channel. It records the
runtime and signer pins read from operator state and the exact capture digest.
On another machine, use an independently built verifier:

```sh
python3 examples/reference-swarm/qualify-process-matrix.py verify \
  --chio /absolute/path/to/independent/chio \
  --artifact /received/matrix.json --trusted-pins /trusted/operator-pins.json
```

Replace `verify` with `test-evidence` to repeat the 15 capture, signature and
semantic substitution checks. The run command executes those checks before
reporting success and retains `negative-verification.json`. Most mutation cases
deliberately update the test capture digest, so they exercise the underlying
signatures and cross-links as well as rejection of transport tampering.

Verification rechecks the original signatures and joins the observations to
the same worker identities, responses, launches and durable accounting. An
operator's file, socket, contention or PID observation remains an external
observation authenticated by the separately retained capture digest. It is not
a signed tool exit. `local_matrix_verified: true` reports that local composition;
`m5_acceptance_complete` stays false pending combined-foundation and designated
platform qualification. Failed commands keep their logs and do not emit a
passing matrix.
