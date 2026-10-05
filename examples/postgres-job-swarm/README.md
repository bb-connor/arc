# PostgreSQL jobs under Chio process authority

This second resource adapter uses the existing `PostgresFindingMarketStore`
lease API. The native MCP adapter binds a worker's lease owner to the exact
capability digest supplied by the Chio kernel. Worker tool arguments cannot
select an owner. PostgreSQL checks owner, fence and expiry in the transaction
that commits a result. The adapter adds no database tables or replay journal.

The operator gets `assign`, `release` and `inspect` through three installed
routes: `jobs-admin-assign`, `jobs-admin-release` and `jobs-admin-inspect`.
Child workers get only `jobs-task`, `jobs-complete` and `jobs-renew`. Each
route uses the existing static `chio-broker-mcp` proxy in an enforced native
cage and a prepared, caller-bound request. Separate authenticated host adapters
fix the worker/operator role and tenant. Only those adapters receive the
production worker database credential. Migration and initial job creation use
separate roles before the host starts.

## Run the native qualification

Requires Linux x86_64, Docker, OpenSSL, Rust and uv. Run from the repository root.
The [PostgreSQL workflow](../../.github/workflows/postgres-job-swarm.yml) runs the
complete fixture, including the
[prepared broker build](../../.github/actions/prepared-native-broker/action.yml)
and [enforced host qualification](../../.github/actions/enforced-native-fixture/action.yml).
For a local run, prepare those same fixtures first. They supply
`CHIO_BROKER_TEST_BINARY`, `CHIO_BROKER_MCP_TOOL`, `CHIO_CAGE_INIT` and
`CHIO_RECEIPT_ANCHOR_ROOT`. The qualification helper uses deterministic fixture
keys and is not a deployment provisioning authority.
The example uses a dedicated PostgreSQL container and named volume. It never
resets another database. Choose a private output directory with ancestry that
passes Chio's native launch checks.

```sh
cargo build --locked -p chio-cli --features real-linux-enforcement --bin chio
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
"$job_root/venv/bin/python" examples/postgres-job-swarm/qualify_claim_loss.py \
  --chio "$job_root/chio" --database-state "$job_root/database/state.json" \
  --output "$job_root/claim-loss"
python3 examples/postgres-job-swarm/postgres.py stop \
  --state "$job_root/database/state.json"
```

Database-only fixtures can run on macOS with OpenSSL 3 through `--openssl`.
The enforced native trajectories require Linux x86_64. The image's local content ID is frozen
before startup; the report records that ID and repository digests. Container
stop preserves its data volume. Private state contains database credentials
and signing material. Export only the qualification report, receipts and
public verification key.

Fixture bootstrap files are copied through the Docker API into its own stopped
container before startup. The daemon does not need access to the client's
temporary paths. The published database port must still be reachable through
local loopback, as with Docker Desktop, Colima or a local Linux daemon.

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

`qualify_claim_loss.py` exercises a different failure boundary. Its test-only
host adapter cut point records a successful response from the real Rust claim
API after PostgreSQL commits, then withholds its HTTPS response. The driver kills the actual
native host with SIGKILL. The installed SDK retains the unresolved request.
After restarting with a fresh socket and rotated credential, two attempts to
recover the identical request must return a verified signed denial retaining
`outcome_unknown_after_dispatch`. The first job remains leased; a second queued
job must remain pending, and the resource adapter must have received exactly one claim.

A deliberately new operation then claims the second job. This control proves
that an accidental redispatch could have caused an observable second effect.
It is new work in an isolated fixture, not a supported retry technique.
The withheld gateway response is test evidence, not a recovered kernel receipt.
This check proves refusal to repeat an uncertain claim. It does not recover
the missing claim outcome or supply an atomic transaction across Chio and
PostgreSQL. The cut point is enabled only by a private qualification configuration, never by a worker request.

The signed uncertainty response can have `terminal_state.state: completed`:
the kernel has completed that evaluation with a denial. This is not evidence
that the resource operation completed or had no effect. Check the verdict and
the receipt's `metadata.admission_operation.projected_state`; this case retains
`outcome_unknown_after_dispatch` and has no resource output.

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

Prepare the resource arguments through the live host before calling
`invoke_recorded`. For example, within the qualification's managed host lifetime:

```python
request = host.prepared_request(
    connections["root"], "assign-release-assessment-1", "assign",
    {"owner_capability_sha256": connections["replacement"]["caller_capability_sha256"],
     "lease_seconds": 600, "limit": 1},
)
response = invoke_recorded(chio, connections["root"], key + "\n", request, output)
```

The retained request's `arguments` contain the original `chio.broker-execute.v1`
envelope. Keep that complete request for recovery. Changing its signed body,
nonce, route or key is a different invocation. The qualification owns its
adapters, brokers and host through context managers and stops them at the end;
retained connection files do not start those services.

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

The metadata digest identifies the original process capability. The host's
prepared broker request binds it to the exact body, installed operation and
original admission. The resource adapter trusts the authenticated broker's
custody of that body. Worker-supplied `_meta` remains ordinary input and cannot
replace it. The static proxy uses enforced native confinement; neither sockets,
process creation nor database credentials are added to its cage. Arbitrary
code running as the trusted host's OS user remains outside this boundary.

The live Python and JavaScript workers expose the original resource schemas
and decode broker application content for the model. Their signed response
artifacts remain unchanged for independent receipt verification.

The first actual worker-role invocation exposed a pre-existing Rust API
mismatch: `begin_tenant` issued `SELECT ... FOR SHARE`, which requires an
UPDATE privilege deliberately withheld from worker logins. The worker
connection passed role checks, then job assignment failed. Job transitions
now perform a nonlocking preliminary tenant read; their existing privileged
SQL functions retain the authoritative tenant lock and enabled-state check.
Job reads and readiness probes use the existing read-only snapshot boundary.
No role grants or migrations were expanded.
