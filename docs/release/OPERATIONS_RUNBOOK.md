# Operations Runbook

This runbook covers the supported self-hosted operator surfaces for the current
bounded Chio release candidate:

- `chio trust serve` for the trust-control plane
- `chio mcp serve-http` for a hosted remote MCP edge
- the receipt dashboard served from the trust-control process

It is intentionally pragmatic and assumes one service owner is operating local
or cluster-contained deployments backed by SQLite state.

## Bounded Operational Profile

The current ship boundary is:

- **trust-control:** local or leader-local single-writer truth with
  deterministic leader selection and eventual repair; not consensus-backed HA
- **hosted auth:** single-node or dedicated-per-session hosted admission with
  explicit sender-constrained access tokens where available; static bearer,
  non-`cnf`, and `shared_hosted_owner` paths are compatibility-only
- **monetary budgets:** single-node atomic on one SQLite store; clustered mode
  admits the documented overrun bound and is not distributed-linearizable
- **receipts and checkpoints:** signed local audit evidence with checkpoint
  export and inclusion-proof material; not public transparency-log semantics

## 1. Required Runtime Inputs

### Trust-Control

Required:

- `--listen`
- `--service-token`

Recommended persistent state:

- `--receipt-db <path>`
- `--revocation-db <path>`
- `--authority-db <path>` for restart-stable authority state on a non-clustered
  authority service
- `--budget-db <path>` when monetary enforcement is enabled

Optional shared registries and federation state:

- `--enterprise-providers-file <path>`
- `--verifier-policies-file <path>`
- `--verifier-challenge-db <path>`
- `--certification-registry-file <path>`
- `--policy <path>` when using reputation-gated issuance or runtime-assurance
  issuance tiers

Clustered deployments additionally require:

- `--advertise-url <public-base-url>`
- one or more `--peer-url <peer-base-url>` values
- `--cluster-node-seed-file <path>` naming this node's strict Ed25519 seed file
- `--cluster-replay-db <path>` naming durable replay state that survives restart
- one `--cluster-member URL=ED25519_PUBLIC_KEY` pin for the advertised node and
  every configured peer

Cluster mode currently requires Linux with `/proc/self/fd` mounted. The replay
database is opened through a retained parent-directory descriptor so SQLite is
cryptographically adjacent to the same file identity that startup validated.
Startup rejects cluster mode on platforms that cannot provide that binding.

Do not combine `--peer-url` with `--authority-seed-file` or `--authority-db`.
Authority snapshots are observational and do not provide a shared authority
write or selector protocol. Clustered authority custody and issuance therefore
fail closed until such a protocol is implemented.

The member URL set must exactly equal the normalized advertised URL plus the
normalized peer URL set. Every member key must be a unique bare Ed25519 public
key. The local seed must match the advertised node's pin. Node membership keys
must be distinct from every current or historical authority signer, authority
workload and session-admission signers, and every configured bearer credential.
The node seed and replay database require trusted ownership, private file mode,
one hard link, no final or ancestor symlink, and a complete trusted parent
chain. The final parent must not grant group or world write authority.

Internal cluster routes do not accept service, admin, tenant, authority
workload, or other bearer credentials. Each request carries an application-level
Ed25519 signature over the HTTP method, internal endpoint, canonical body
digest, intended receiver URL, current cluster term when applicable, freshness
timestamp, UUIDv4 nonce, and pinned peer identity. HTTPS certificate and private-CA validation
remain mandatory outside explicitly enabled local development. Reverse-proxy
mTLS can add defense in depth, but it does not replace application-level member
pins.

The cluster replay database is part of the security boundary. Back it up and
restore it with the node's other SQLite state. Do not delete, recreate, or roll
it back independently while the node seed remains active, because doing so can
make previously consumed signed requests replayable. Replay pruning uses a
transactionally persisted maximum-observed-time watermark. A clock rollback
beyond the authentication skew fails closed rather than reopening a pruned
nonce window.

There is no network route for partition fault injection. Qualification must
isolate processes with the test harness, network namespace, firewall, or proxy
layer outside the production service API.

Cluster node identity rotation is coordinated configuration work:

1. Generate a new strict seed for the target node without replacing the active
   seed in place.
2. Derive its Ed25519 public key and update that node's member pin in every
   node's complete membership configuration.
3. Stop cluster traffic and the target node. A mixed pin set intentionally
   fails closed, so do not expect an uncoordinated rolling rotation to converge.
4. Atomically install the new seed and the matching membership configuration,
   then restart all affected nodes.
5. Verify cluster health and confirm that requests signed by the retired key
   are rejected.

Membership authentication proves only that a request came from a pinned
cluster node. It never grants capability issuance or authority rotation rights.
The leader must independently validate the configured authority workload or
administrator role for every privileged authority mutation.

### Remote MCP Edge

Required:

- `--policy <path>` and an exact `--server-id`, `--server-name`, and
  `--server-version`
- `--signed-manifest <path>` and the independent registered
  `--manifest-public-key <key>`
- `--cage-policy <path>` and the independent
  `--cage-policy-signer <key>`
- an absolute wrapped executable and argv that exactly match the signed cage
  policy
- durable local authority custody through `--authority-seed-file` or
  `--authority-db`

Recommended persistent state:

- `--receipt-db <path>`
- `--revocation-db <path>`
- `--authority-db <path>` or `--authority-seed-file <path>`
- `--budget-db <path>` when monetary enforcement is enabled
- `--session-db <path>` for restart-stable tombstones

When `--control-url` is configured, the remote service owns receipts,
revocations, and budgets. Do not also configure local `--receipt-db`,
`--revocation-db`, or `--budget-db`. The locally selected authority signer must
equal `--control-authority-public-key`.

Optional auth and federation inputs:

- one auth mode: `--auth-token`, `--auth-jwt-public-key`, or `--auth-introspection-url`
- `--admin-token <token>` for remote admin APIs
- `--auth-server-seed-file <path>` for local JWT issuance
- `--identity-federation-seed-file <path>` for stable subject derivation
- `--enterprise-providers-file <path>` for enterprise-origin federation lanes

Bounded hosted/auth recommendation:

- prefer dedicated-per-session hosting
- require explicit sender-constrained access tokens with `cnf` where the
  hosted authorization surface is part of the security boundary
- treat `--auth-token`, non-`cnf` JWT/introspection tokens, random per-session
  subject fallback, and `shared_hosted_owner` as compatibility-only paths

Hosted session lifecycle tuning now uses these canonical env names:

- `CHIO_MCP_SESSION_IDLE_EXPIRY_MILLIS`
- `CHIO_MCP_SESSION_DRAIN_GRACE_MILLIS`
- `CHIO_MCP_SESSION_REAPER_INTERVAL_MILLIS`
- `CHIO_MCP_SESSION_TOMBSTONE_RETENTION_MILLIS`

### Remote Trust-Control Client Security

Configure `--control-url` with final HTTPS origins. A comma-separated endpoint
list is supported. Chio does not follow redirects. Literal IPv4 and IPv6
loopback HTTP endpoints are accepted for local development only.

For private PKI:

```bash
export CHIO_CONTROL_TLS_ROOT_CA_FILE=/etc/chio/control-root-ca.pem
```

The file must be a nonempty regular file, must not be a symlink, must be no
larger than 1 MiB, and must contain valid PEM certificates. When configured,
this file replaces the ambient public WebPKI root set for every control
endpoint in the process.

Control-backed runtime composition also requires the exact current authority
pin:

```bash
export CHIO_CONTROL_AUTHORITY_PUBLIC_KEY=<current-ed25519-public-key>
export CHIO_CONTROL_AUTHORITY_TRUSTED_PUBLIC_KEYS=<prior-key-1>,<prior-key-2>
```

The current key authenticates fresh authority status and lookup envelopes.
Prior keys authenticate only durable artifacts created before rotation. The
complete current and historical set is limited to 256 unique keys.

Authority rotation procedure:

1. Read and retain `publicKey` and `trustedPublicKeys` from each endpoint's
   authenticated `GET /v1/authority` response.
2. Rotate through authenticated `POST /v1/authority`.
3. Wait until every endpoint reports the same new `publicKey`, generation, and
   trusted history.
4. Move the old current key into
   `CHIO_CONTROL_AUTHORITY_TRUSTED_PUBLIC_KEYS` and set the new key as
   `CHIO_CONTROL_AUTHORITY_PUBLIC_KEY`.
5. Select that same new signer in each hosted edge's local authority custody.
6. Restart edges. Existing clients do not reload authority environment values.
7. Verify that a new session uses the new issuer and that a retained
   pre-rotation artifact still verifies.

For CA rotation, first deploy a regular bundle containing both old and new
roots and restart clients. Rotate server certificates, then remove the old root
and restart clients again.

## 2. Initial Deployment Procedure

### Supervised deployment and shutdown grace (systemd)

Run trust-control, the remote MCP edge, and the pheromone relay under a
supervisor in production so a crash auto-restarts and a stop leaves a grace
window for the graceful drain. Reference units ship under
`docs/release/systemd/` (trust-control, MCP edge) and
`docs/release/chio-pheromone-relay/systemd/` (relay). The raw `chio ... serve`
commands shown below are for local development and one-off runs.

```bash
install -m 0644 docs/release/systemd/chio-trust-control.service /etc/systemd/system/
install -m 0644 docs/release/systemd/chio-mcp-edge.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now chio-trust-control.service chio-mcp-edge.service
```

Each service installs a SIGTERM handler and drains in-flight requests before it
exits, bounded by a 25s drain deadline. The units set `KillSignal=SIGTERM` and
`TimeoutStopSec=35s` (the drain deadline plus a flush margin) so systemd only
escalates to SIGKILL after the drain can finish.

Deploy contract: set the platform stop grace period at least as high as
`TimeoutStopSec` so the drain is not preempted. On managed platforms that means
Cloud Run `timeoutSeconds`, ECS `stopTimeout`, or Kubernetes
`terminationGracePeriodSeconds` >= 35s. The per-process memory and OOM directives
(`MemoryMax`, `OOMScoreAdjust`, `LimitNOFILE`, `vm.overcommit_memory`) are owned
by the bounded-memory deployment guidance; set them in these units from that
single source of truth.

### Trust-Control

1. Create a dedicated state directory, for example:

   ```bash
   mkdir -p /var/lib/chio /etc/chio
   ```

2. Place policy and registry files under `/etc/chio` and SQLite state under
   `/var/lib/chio`.

3. Start the service:

   ```bash
   chio trust serve \
     --listen 127.0.0.1:8940 \
     --service-token "$CHIO_SERVICE_TOKEN" \
     --receipt-db /var/lib/chio/receipts.sqlite3 \
     --revocation-db /var/lib/chio/revocations.sqlite3 \
     --authority-db /var/lib/chio/authority.sqlite3 \
     --budget-db /var/lib/chio/budgets.sqlite3 \
     --enterprise-providers-file /etc/chio/enterprise-providers.json \
     --verifier-policies-file /etc/chio/verifier-policies.json \
     --verifier-challenge-db /var/lib/chio/verifier-challenges.sqlite3 \
     --certification-registry-file /etc/chio/certifications.json
   ```

4. Verify service readiness:

   ```bash
   curl -s http://127.0.0.1:8940/health | jq
   curl -s -H "Authorization: Bearer $CHIO_SERVICE_TOKEN" \
     http://127.0.0.1:8940/v1/authority | jq
   ```

### Remote MCP Edge

1. Provision a signed manifest, its registered publisher key, a signed cage
   policy, its independent policy signer, a durable migration ledger, and a
   local authority seed whose public key equals the current control pin.

2. Start the wrapped edge with remote control, persistent session tombstones,
   and explicit admin auth:

   ```bash
   export CHIO_CONTROL_TLS_ROOT_CA_FILE=/etc/chio/control-root-ca.pem
   export CHIO_CONTROL_TOKEN=<service-token>
   export CHIO_EDGE_TOKEN=<edge-admission-token>
   export CHIO_ADMIN_TOKEN=<admin-token>
   export CHIO_CONTROL_AUTHORITY_PUBLIC_KEY=<current-ed25519-public-key>
   test "$CHIO_ADMIN_TOKEN" != "$CHIO_EDGE_TOKEN"
   test "$CHIO_ADMIN_TOKEN" != "$CHIO_CONTROL_TOKEN"
   test "$CHIO_EDGE_TOKEN" != "$CHIO_CONTROL_TOKEN"

   chio \
     --authority-seed-file /etc/chio/mcp-edge-authority.seed \
     --control-url https://trust-control.example.com \
     mcp serve-http \
     --policy examples/policies/canonical-hushspec.yaml \
     --server-id demo-server \
     --server-name "Demo Server" \
     --server-version 1.0.0 \
     --signed-manifest /etc/chio/demo-server-signed-manifest.json \
     --manifest-public-key "$CHIO_MANIFEST_PUBLIC_KEY" \
     --cage-policy /etc/chio/demo-server-cage-policy.json \
     --cage-policy-signer "$CHIO_CAGE_POLICY_SIGNER" \
     --listen 127.0.0.1:8931 \
     --auth-token "$CHIO_EDGE_TOKEN" \
     --admin-token "$CHIO_ADMIN_TOKEN" \
     --session-db /var/lib/chio/edge-sessions.sqlite3 \
     -- \
     /usr/bin/python3 /opt/chio/mcp-server.py
   ```

3. Initialize one session and confirm the admin diagnostics surface:

   ```bash
   curl -s -H "Authorization: Bearer $CHIO_ADMIN_TOKEN" \
     http://127.0.0.1:8931/admin/health | jq
   curl -s -H "Authorization: Bearer $CHIO_ADMIN_TOKEN" \
     http://127.0.0.1:8931/admin/sessions | jq
   ```

### Dashboard

The dashboard is served by `chio trust serve` from `crates/products/chio-cli/dashboard/dist`.
Build it before deployment:

```bash
./scripts/check-dashboard-release.sh
```

Then load:

```text
https://trust-control.example.com/?token=<service-token>
```

## 3. Configuration Checks Before Promotion

Run the production qualification lane from the repo root:

```bash
./scripts/qualify-release.sh
```

For the ship-facing bounded release gate specifically:

```bash
cargo xtask qualify bounded-chio
./scripts/qualify-trust-control.sh
```

Minimum deploy-time smoke checks:

```bash
./scripts/check-release-inputs.sh
./scripts/check-dashboard-release.sh
./scripts/check-chio-ts-release.sh
./scripts/check-chio-py-release.sh
./scripts/check-chio-go-release.sh
```

### Receipt Store Operations

Receipt writer and checkpoint operations are local SQLite operations in this
release. Run them on the node that owns the receipt database:

```bash
chio receipt health --receipt-db /var/lib/chio/receipts.sqlite3
chio receipt flush --receipt-db /var/lib/chio/receipts.sqlite3 --timeout-ms 5000
chio receipt checkpoint status --receipt-db /var/lib/chio/receipts.sqlite3
chio receipt checkpoint create \
  --receipt-db /var/lib/chio/receipts.sqlite3 \
  --kernel-seed-file /etc/chio/kernel.seed \
  --max-batch 1000
chio receipt checkpoint verify --receipt-db /var/lib/chio/receipts.sqlite3
```

Use `--json` for automation. The envelope `schema` value is stable and the
`report` keeps null fields present for optional checkpoint and error values.

Human output includes the committed and checkpointed entry sequences, the
uncheckpointed range, writer counters, database size, WAL checkpoint
observation, checkpoint sequence, next range, and checkpoint or writer errors.
`chio receipt checkpoint status` and `chio receipt checkpoint verify` exit
non-zero when checkpoint chain or projection integrity fails.

`--timeout-ms` on `chio receipt flush` is the receipt writer flush-barrier
timeout. It does not bound the entire command.

Remote control-plane receipt health, flush, and checkpoint operations are
deferred. Passing `--control-url` fails with:

```text
requires local --receipt-db; remote receipt write operations are not supported in this release
```

### Launch And Partner Evidence Handoff

Before promoting a candidate outside the operator boundary, archive and attach:

- `target/release-qualification/conformance/mcp-core/report.md`
- `target/release-qualification/conformance/tasks/report.md`
- `target/release-qualification/conformance/auth/report.md`
- `target/release-qualification/conformance/notifications/report.md`
- `target/release-qualification/conformance/nested-callbacks/report.md`
- `target/release-qualification/logs/trust-cluster-repeat-run.log`
- [RELEASE_AUDIT.md](RELEASE_AUDIT.md)
- [PARTNER_PROOF.md](PARTNER_PROOF.md)
- [CHIO_RECEIPTS_PROFILE.md](../standards/CHIO_RECEIPTS_PROFILE.md)
- [CHIO_PORTABLE_TRUST_PROFILE.md](../standards/CHIO_PORTABLE_TRUST_PROFILE.md)

Do not promote from local qualification evidence alone. Hosted `CI` and
`Release Qualification` workflow results are still required before external
tag/publication.

## 4. Backup Procedure

Stop write traffic or place the service in a maintenance window before taking
authoritative backups.

Back up SQLite state:

```bash
sqlite3 /var/lib/chio/receipts.sqlite3 ".backup '/var/backups/chio/receipts.sqlite3'"
sqlite3 /var/lib/chio/revocations.sqlite3 ".backup '/var/backups/chio/revocations.sqlite3'"
sqlite3 /var/lib/chio/authority.sqlite3 ".backup '/var/backups/chio/authority.sqlite3'"
sqlite3 /var/lib/chio/budgets.sqlite3 ".backup '/var/backups/chio/budgets.sqlite3'"
sqlite3 /var/lib/chio/cluster-replay.sqlite3 ".backup '/var/backups/chio/cluster-replay.sqlite3'"
sqlite3 /var/lib/chio/verifier-challenges.sqlite3 ".backup '/var/backups/chio/verifier-challenges.sqlite3'"
sqlite3 /var/lib/chio/edge-sessions.sqlite3 ".backup '/var/backups/chio/edge-sessions.sqlite3'"
```

Back up file-backed registries and policies:

For clustered nodes, also back up the strict cluster node seed with its `0600`
mode preserved. Store it separately from general database backups and restore
it only together with the matching member pin configuration.

```bash
cp /etc/chio/enterprise-providers.json /var/backups/chio/
cp /etc/chio/verifier-policies.json /var/backups/chio/
cp /etc/chio/certifications.json /var/backups/chio/
cp /etc/chio/*.yaml /var/backups/chio/
```

Record the binary version and git commit used for the backup snapshot.

## 5. Restore Procedure

1. Stop the affected `chio trust serve` or `chio mcp serve-http` process.
2. Restore the SQLite files into the exact paths expected by the service.
3. Restore the file-backed registries and policies.
4. Restart the process with the same command-line arguments used before the
   incident.
5. Re-run the smoke checks:

   ```bash
   curl -s http://127.0.0.1:8940/health | jq
   curl -s -H "Authorization: Bearer $CHIO_SERVICE_TOKEN" \
     http://127.0.0.1:8940/v1/authority | jq
   curl -s -H "Authorization: Bearer $CHIO_ADMIN_TOKEN" \
     http://127.0.0.1:8931/admin/health | jq
   curl -s -H "Authorization: Bearer $CHIO_ADMIN_TOKEN" \
     http://127.0.0.1:8931/admin/sessions | jq
   ```

## 6. Upgrade Procedure

1. Run `./scripts/qualify-release.sh` on the candidate commit.
2. Build or obtain the exact candidate binary set.
3. Take backups using the backup procedure above.
4. Stop write traffic or drain external callers.
5. Stop the running Chio processes.
6. Replace the binary with the qualified candidate.
7. Restart `chio trust serve` first, then any dependent `chio mcp serve-http`
   edges.
8. Run post-upgrade smoke checks:

   ```bash
   curl -s http://127.0.0.1:8940/health | jq
   curl -s -H "Authorization: Bearer $CHIO_ADMIN_TOKEN" \
     http://127.0.0.1:8931/admin/health | jq
   curl -s -H "Authorization: Bearer $CHIO_ADMIN_TOKEN" \
     http://127.0.0.1:8931/admin/sessions | jq
   ```

9. If SDK artifacts are being published with the same release, run:

   ```bash
   ./scripts/check-chio-ts-release.sh
   ./scripts/check-chio-py-release.sh
   ./scripts/check-chio-go-release.sh
   ```

## 7. Rollback Procedure

Rollback is a full binary-and-state rollback to the last known good backup.

1. Stop the candidate processes.
2. Restore the previous binaries.
3. Restore the backed-up SQLite and registry files if the candidate performed
   writes that must be discarded.
4. Restart the previous version with the original arguments.
5. Re-run the same health and admin smoke checks used in the upgrade procedure.
6. Record the failed candidate commit and attach the qualification logs and any
   cluster/admin diagnostics to the incident report.

## 8. Incident Triage Pointers

- Trust-control cluster convergence: check `/health` externally and inspect
  `/v1/internal/cluster/status` only through a pinned node-to-node diagnostic
  request. Operator bearer tokens cannot authenticate internal routes.
- Authority rotation or trust drift: check `/v1/authority`
- Remote runtime lifecycle/auth failures: check `/admin/health`,
  `/admin/sessions`, and `/admin/sessions/{session_id}/trust`
- Receipt/export gaps: check `/v1/reports/operator`,
  `/v1/federation/evidence-shares`, and the dashboard summary panels

See [OBSERVABILITY.md](./OBSERVABILITY.md) for the diagnostic contract and the
meaning of the main health/admin fields.
