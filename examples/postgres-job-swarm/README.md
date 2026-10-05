# PostgreSQL jobs under Chio process authority

The enforced native qualification uses a host-owned PostgreSQL resource adapter
behind the existing credential broker. Six fixed routes expose only `task`,
`complete`, `renew`, `assign`, `release` and `inspect`. Each route has a dedicated
credential and server ID (`jobs-task`, `jobs-complete`, and so on). Children
receive only the first three grants; the root receives the operator grants.

The confined static MCP target receives neither a database credential nor
socket permission. The host derives the caller digest from the original process
capability inside durable preparation. The authenticated resource channel pins
the tenant and operation. PostgreSQL checks owner, fence and expiry in the same
transaction that commits a result. Migration and initial job creation use
separate operator roles. The adapter adds no database tables or replay journal.

## Qualification boundaries

`qualify_resource.py` exercises the real TLS adapter and worker database role.
It does not qualify a cage, kernel receipt or broker proof. It refuses invalid
credentials, another tenant, another operation and worker-supplied caller
metadata, then exercises assignment, supersession, release and completion.

`qualify.py` and `qualify_claim_loss.py` additionally require the enforcing native
fixture and prepared-broker helper supplied by
[the PostgreSQL workflow](../../.github/workflows/postgres-job-swarm.yml).
Run that workflow on a real Linux x86_64 host. Its adjacent native fixture gate
must pass before the complete scenarios execute. The broker helper supplies
explicit isolated qualification identities and migration fixtures; it does not
supply production deployment approval. Every serving broker, process host and
resource uses its production implementation.

The native scenarios require:

- Rejection of a superseded caller using the replacement's current fence.
- Refusal of caller spoofing and a child's operator request.
- Completion by the replacement and byte-identical receipt recovery after restart.
- Separation of the original `completed` outcome from `already_completed` on a
  deliberately new logical call.
- A host SIGKILL after a committed claim and before its response, followed by
  recovery of the original operation without claiming a second queued job.
- A separate new-intent control that proves the second job was claimable.

The fault directory and credential files are outside the empty native working
directory. The supervisor keeps brokers alive across process-host restarts and
closes their control pipe before stopping its service children. Logical intent
and the exact prepared wire request are retained separately; the receipt
verifier checks the wire request without rewriting signed evidence.

The committed-claim-loss control uses an explicit host-owned fault gate. Once
PostgreSQL returns the committed result, the gate records it and withholds the
HTTPS response. The driver kills the process host and releases that exchange.
Two recovery attempts must retain `outcome_unknown_after_dispatch`, one original
request identity and no resource output. The first job stays leased and the
second stays pending. The explicit new-intent control then claims the second job.
The withheld resource result is test evidence, not a recovered kernel receipt
or an atomic transaction across Chio and PostgreSQL.

## Local resource component check

Requires Docker, OpenSSL and Rust. This command checks the TLS/database component
on the local host; complete native qualification still requires the workflow.

```sh
cargo build --locked -p chio-finding-market-store-postgres --example agent_jobs
umask 077
job_root=$(mktemp -d)
cp target/debug/examples/agent_jobs "$job_root/agent-jobs"
docker pull postgres:17.11
python3 examples/postgres-job-swarm/postgres.py start \
  --binary "$job_root/agent-jobs" --output "$job_root/database"
python3 examples/postgres-job-swarm/qualify_resource.py \
  --database-state "$job_root/database/state.json" --output "$job_root/component"
python3 examples/postgres-job-swarm/postgres.py stop \
  --state "$job_root/database/state.json"
```

The fixture freezes the local PostgreSQL image by content ID. It provisions only
its own container and named volume, copies bootstrap files through the Docker
API, and requires reachable loopback networking. Stop preserves its data volume.
Private state contains credentials and signing material; export only selected
qualification reports, receipts and public verification keys.

## Live and operator consumers

The existing `live.py` cross-framework handoff is retained, but its framework
consumer adaptation and live qualification remain open. Isolated qualification
identities must not become a production deployment recipe. Production
provisioning requires `CHIO_JOB_BROKER_CONFIG` to name an operator-owned
process-host configuration with the six fixed mappings for its tenant, and
operator supervision of those brokers and the resource. This configuration is
necessary, but does not by itself qualify the live consumer path.

Native callers prepare through the trusted process host before invocation.
`invocation.py` preserves logical arguments separately from the signed prepared
request and delegates receipt verification to `chio_process.invocation` using
that exact wire request. Keep the original operation key and recovery policy;
an uncertain effect does not authorize a new logical operation.

A signed uncertainty response can have `terminal_state.state: completed` because
the kernel completed its evaluation with a denial. Check both the verdict and
`metadata.admission_operation.projected_state`. This fixture proves no
population success rate, live-model advantage or independent adoption.
