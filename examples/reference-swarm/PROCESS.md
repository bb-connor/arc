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
