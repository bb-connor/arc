# PostgreSQL jobs under Chio process authority

This second resource adapter uses the existing `PostgresFindingMarketStore`
lease API. The native MCP adapter binds a worker's lease owner to the exact
capability digest supplied by the Chio kernel. Worker tool arguments cannot
select an owner. PostgreSQL checks owner, fence and expiry in the transaction
that commits a result. The adapter adds no database tables or replay journal.

The operator gets `assign`, `release` and `inspect` on `jobs-admin`.
Child workers get only `task`, `complete` and `renew` on `jobs`. Both tool
servers use the production worker database role. Migration and initial job
creation use separate roles before the host starts.

## Run the native qualification

Requires Docker, OpenSSL, Rust and uv. Run from the repository root.
The example uses a dedicated PostgreSQL container and named volume. It never
resets another database. Choose a private output directory with ancestry that
passes Chio's native launch checks.

```sh
cargo build --locked -p chio-cli --bin chio
cargo build --locked -p chio-finding-market-store-postgres --example agent_jobs
umask 077
job_root=$(mktemp -d)
cp target/debug/chio "$job_root/chio"
cp target/debug/examples/agent_jobs "$job_root/agent-jobs"
chmod 700 "$job_root/chio" "$job_root/agent-jobs"
uv build sdks/python/chio-process --wheel --out-dir "$job_root/wheels"
uv venv "$job_root/venv"
uv pip install --python "$job_root/venv/bin/python" --no-deps \
  "$job_root/wheels/chio_process-0.1.0-py3-none-any.whl"
docker pull postgres:17.11
python3 examples/postgres-job-swarm/postgres.py start \
  --binary "$job_root/agent-jobs" --output "$job_root/database"
python3 examples/postgres-job-swarm/check_api.py \
  --database-state "$job_root/database/state.json"
"$job_root/venv/bin/python" examples/postgres-job-swarm/qualify.py \
  --chio "$job_root/chio" --database-state "$job_root/database/state.json" \
  --output "$job_root/qualification"
python3 examples/postgres-job-swarm/postgres.py stop \
  --state "$job_root/database/state.json"
```

On macOS, use an OpenSSL 3 executable through `--openssl` if the system
OpenSSL lacks the certificate options. The image's local content ID is frozen
before startup; the report records that ID and repository digests. Container
stop preserves its data volume. Private state contains database credentials
and signing material. Export only the qualification report, receipts and
public verification key.

The public API regression exercises all six job transitions using
`connect_worker`, including forbidden runtime writes and disabled tenants.
The native qualification then checks:

- Operator assignment, release to a pending state, and replacement assignment.
- Rejection of an old caller using the replacement's current fence.
- Rejection of owner spoofing, missing caller metadata and a child's operator call.
- Completion by the replacement and byte-identical receipt recovery after a
  real host restart.
- The difference between original operation replay (`completed`) and a new
  logical call for an already-retained result (`already_completed`).

These checks use scripted tool requests and synthetic job evidence. They do
not establish a live-model success rate, an independent adopter, or a
performance improvement over an application already using correctly fenced
PostgreSQL jobs.

## Live cross-framework handoff

After preparing the fixture above, install the locked LangGraph environment
and an [AI SDK consumer](../shared-resource-swarm/README.md). Supply the provider
credential in the model worker environment, then run:

```sh
uv sync --project sdks/python/chio-langgraph --locked --extra dev --extra process
sdks/python/chio-langgraph/.venv/bin/python examples/postgres-job-swarm/live.py \
  --chio "$job_root/chio" --gateway "$job_root/agent-jobs" \
  --database-state "$job_root/database/state.json" \
  --consumer /path/to/installed/ai7 --provider openrouter \
  --model openai/gpt-4.1-mini --old-framework langgraph \
  --output "$job_root/live-handoff"
```

The database must still be running. Choose `--old-framework ai-sdk` and a fresh
output directory to reverse the handoff. Each run uses a new tenant and job.
The old worker resumes and finishes before the replacement starts. Acceptance
requires a live old-worker completion attempt with the **current** fence that
returns `superseded`, followed by the replacement's correct committed result.
All original model responses and tool receipts are retained; the report checks
exact receipt replay and verifies the kernel signatures. The task remains a
synthetic assessment, and a passing run is not a population success rate.

## Operator client

`chio_process.invocation` uses the public `ProcessClient`, requires a stable
operation key, retains the request before invoking, and verifies the returned
receipt against an operator-selected kernel public key.

A request file has this shape:

```json
{
  "operation_key": "assign-release-assessment-1",
  "server_id": "jobs-admin",
  "tool_name": "assign",
  "arguments": {
    "owner_capability_sha256": "<digest from the child's private connection descriptor>",
    "lease_seconds": 600,
    "limit": 1
  },
  "known_outcome_only": true
}
```

```sh
"$job_root/venv/bin/python" -m chio_process.invocation \
  --chio "$job_root/chio" \
  --connection "$job_root/qualification/root/connection.json" \
  --trusted-kernel-pubkey "$job_root/qualification/kernel.pub" \
  --request request.json --output "$job_root/operator-attempt-1"
```

This invocation requires the corresponding host to be running. The
qualification starts and stops its host internally; retained credentials do
not start a host.

Keep the same key, arguments **and recovery policy** on every recovery
attempt. `known_outcome_only` defaults to true here. It permits the first
dispatch and recovery of a completed result, but refuses automatic
redispatch of an unknown outcome. It is not a read-only outcome query.
Changing the policy on an existing key conflicts.

The resource's claim operation has no request identity parameter. A lost
claim outcome therefore cannot be repaired by submitting a new key and
pretending it is a retry. Inspecting a job is an observation, not proof that
a particular uncertain claim committed. Releasing and claiming are separate
transactions with an explicit pending intermediate state.

## Boundary and measured integration defect

The metadata digest is an identity binding on a trusted kernel-owned pipe.
It is neither a bearer credential nor an independently signed assertion.
The demo's signed native launch policy does not provide OS containment.
Arbitrary code running as the host's OS user is outside this qualification.

The first actual worker-role invocation exposed a pre-existing Rust API
mismatch: `begin_tenant` issued `SELECT ... FOR SHARE`, which requires an
UPDATE privilege deliberately withheld from worker logins. The worker
connection passed role checks, then job assignment failed. Job transitions
now perform a nonlocking preliminary tenant read; their existing privileged
SQL functions retain the authoritative tenant lock and enabled-state check.
Job reads and readiness probes use the existing read-only snapshot boundary.
No role grants or migrations were expanded.
