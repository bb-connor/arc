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
- **native MCP launch:** exact publisher and cage-policy trust roots, immutable
  executable and argv bindings, and fail-closed cage launch are mandatory; the
  demo provisioner remains migration stage `Disabled` and is not containment

## 1. Required Runtime Inputs

### Trust-Control

Required:

- `--listen`
- `--service-token`
- `--authority-workload-token` when remote MCP edges request capability
  issuance from this service; it must differ from the service, edge, session,
  admin, and tenant-read bearers

Recommended persistent state:

- `--receipt-db <path>`
- `--revocation-db <path>`
- `--authority-db <path>` for clustered or restart-stable authority state
- `--budget-db <path>` when monetary enforcement is enabled

Witnessed authority custody is an opt-in single-node profile. It requires all
of the following together:

- `--authority-seed-file <path>` for the active authority key
- `--authority-keyring-config <path>` for the durable key log and fixed trust
  topology
- `--receipt-db <path>` for key-transition receipt forwarding
- `--authority-workload-token` distinct from every other bearer

Do not combine this profile with `--authority-db` or any `--peer-url`. Startup
contacts all three configured witnesses and both auditors, validates their
independent durable identities, verifies the enforced migration ledger, and
fails before binding the listener when any requirement is unavailable. While
the profile is active, legacy routes that load the authority seed directly are
disabled and deny rather than bypass witnessed signing custody.

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

### Remote MCP Edge

Required:

- `--policy <path>` and `--server-id <id>`
- `--signed-manifest <path>` and the independently registered
  `--manifest-public-key <hex>`
- `--cage-policy <path>` and the independently pinned
  `--cage-policy-signer <hex>`
- an exact absolute wrapped executable and argv matching the cage policy

Recommended persistent state:

- `--receipt-db <path>`
- `--session-db <path>` for the joint durable admission authority and
  restart-stable remote session state
- `--resume-hmac-keyring <path>` whenever `--session-db` is present
- in local-authority mode, `--authority-db <path>` or
  `--authority-seed-file <path>`; do not combine separate `--revocation-db` or
  `--budget-db` stores with the joint `--session-db`
- in trust-control mode, `--control-url`, the administrative
  `--control-token`, the distinct `--remote-authority-workload-token`, and the
  exact `--control-authority-public-key`; provide every additional key in the
  service trust set with repeated `--control-authority-trusted-public-keys`

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
   `/var/lib/chio`. Set `CHIO_TRUST_SERVICE_TOKEN` and the distinct
   `CHIO_TRUST_AUTHORITY_WORKLOAD_TOKEN` through the supervisor's protected
   environment or secret injection mechanism.

3. Start the service:

   ```bash
   chio trust serve \
     --listen 127.0.0.1:8940 \
     --authority-workload-token "$CHIO_TRUST_AUTHORITY_WORKLOAD_TOKEN" \
     --receipt-db /var/lib/chio/receipts.sqlite3 \
     --authority-db /var/lib/chio/authority.sqlite3 \
     --session-db /var/lib/chio/trust-sessions.sqlite3 \
     --enterprise-providers-file /etc/chio/enterprise-providers.json \
     --verifier-policies-file /etc/chio/verifier-policies.json \
     --verifier-challenge-db /var/lib/chio/verifier-challenges.sqlite3 \
     --certification-registry-file /etc/chio/certifications.json
   ```

4. Verify service readiness:

   ```bash
   curl -s http://127.0.0.1:8940/health | jq
   curl -s -H "Authorization: Bearer $CHIO_TRUST_SERVICE_TOKEN" \
     http://127.0.0.1:8940/v1/authority | jq
   ```

For witnessed authority custody, provision the operator log, three witness
services, two audit services, the artifact-time signer, and the enforced
enterprise migration ledger described in
`crates/security/chio-keyring/README.md`. Replace `--authority-db` in the
command above with:

```bash
--authority-seed-file /run/credentials/chio/authority.seed \
--authority-keyring-config /etc/chio/authority-keyring.yaml
```

After startup, verify the backend reports `enterprise_keyring` and fetch a
canonical synchronization response with the administrative service token:

```bash
curl -s -H "Authorization: Bearer $CHIO_TRUST_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://127.0.0.1:8940/v1/authority/key-log/sync | jq
```

### Remote MCP Edge

1. Obtain the publisher-signed manifest, signed cage policy, and their public
   keys through independent registration. Ensure the exact executable, argv,
   working directory, file digests, and operator ceilings match the signed cage
   policy. `chio security provision-native-mcp-demo` creates demo-only private
   signers at migration stage `Disabled`; it must not be used as evidence of
   production containment.

2. Create a dedicated session HMAC keyring as a regular mode `0600` file under
   a mode `0700` operator-owned directory. Generate each `keyBase64` from 32
   random bytes encoded as unpadded base64url. Do not reuse an authority seed,
   bearer token, manifest key, or cage receipt key.

   ```json
   {
     "schema": "chio.remote-mcp.resume-hmac-keyring.v1",
     "current": {
       "keyId": "edge-resume-2026-09",
       "version": 1,
       "keyBase64": "REPLACE_WITH_43_CHARACTER_BASE64URL_SECRET"
     },
     "previous": []
   }
   ```

3. Start the wrapped edge with persistent state, explicit admin auth, separate
   control credentials, and exact trust pins. The environment values shown
   below must be distinct where required.

   ```bash
   chio mcp serve-http \
     --policy examples/policies/canonical-hushspec.yaml \
     --server-id demo-server \
     --listen 127.0.0.1:8931 \
     --signed-manifest /etc/chio/mcp-signed-manifest.json \
     --manifest-public-key "$CHIO_MANIFEST_PUBLIC_KEY" \
     --cage-policy /etc/chio/mcp-cage-policy.json \
     --cage-policy-signer "$CHIO_CAGE_POLICY_SIGNER" \
     --control-url http://127.0.0.1:8940 \
     --control-authority-public-key "$CHIO_CONTROL_AUTHORITY_PUBLIC_KEY" \
     --admin-token "$CHIO_ADMIN_TOKEN" \
     --remote-authority-workload-token "$CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN" \
     --session-db /var/lib/chio/edge-sessions.sqlite3 \
     --resume-hmac-keyring /etc/chio/edge-resume-hmac-keyring.json \
     -- \
     /usr/local/bin/chio-mcp-upstream
   ```

   Supply `CHIO_AUTH_TOKEN`, `CHIO_ADMIN_TOKEN`, `CHIO_CONTROL_TOKEN`, and
   `CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN` through protected environment or
   secret injection. The command rejects a workload token equal to a service,
   session, or admin token.

4. Initialize one session and confirm the admin diagnostics surface:

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
http://127.0.0.1:8940/?token=<service-token>
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

## 4. Key Rotation Procedures

### Remote authority keys

Authority pins are exact by design. An edge does not automatically trust a new
current key just because trust-control reports it.

1. Read and archive `/v1/authority` with the administrative service token.
2. Rotate the authority with the administrative service token.
3. Drain each edge. Existing cached capabilities can remain usable until their
   normal expiry or revocation, but new issuance fails closed while the edge's
   current-key pin is stale.
4. Set `--control-authority-public-key` to the new current key and provide the
   complete remaining historical trust set with repeated
   `--control-authority-trusted-public-keys` flags.
5. Restart the edge and verify `/admin/health`, initialize a new session, and
   confirm its capability issuer is the new key.

Do not remove a historical authority key until every capability it issued is
outside its validity and recovery window.

When trust-control reports `enterprise_keyring`, step 2 performs a witnessed
rotation. It writes a crash-safe pending seed handoff, appends and checkpoints
the rotation, obtains the configured witness quorum and both auditor
acknowledgements, activates the selector, and only then replaces the active
seed. A timeout or partial response is not permission to rotate the seed by
hand. Preserve the active seed, any `.chio-keyring-pending` handoff, operator
log, migration ledger, and all independent witness and auditor stores until the
runtime can resume or an incident procedure proves the durable state.

### Remote session HMAC keys

1. Drain the edge and back up both the session database and keyring as one
   recovery unit.
2. Generate a new independent 32-byte key, choose a strictly greater version,
   and make it `current`.
3. Move the old current key into `previous` with `verifyUntilMillis` no later
   than seven days in the future. At most four previous keys are accepted.
4. Restart once with both keys so existing records can be verified. Subsequent
   persistence signs records with the current key.
5. Remove an old key only after its verification deadline and after all sessions
   that could still carry it have expired or been terminalized.

Missing, expired, duplicated, malformed, overly permissive, or incorrectly
owned keyrings fail startup or session restoration closed. A keyring without
its matching database is not a usable backup.

## 5. Backup Procedure

Stop write traffic or place the service in a maintenance window before taking
authoritative backups.

Back up SQLite state:

```bash
sqlite3 /var/lib/chio/receipts.sqlite3 ".backup '/var/backups/chio/receipts.sqlite3'"
sqlite3 /var/lib/chio/revocations.sqlite3 ".backup '/var/backups/chio/revocations.sqlite3'"
sqlite3 /var/lib/chio/authority.sqlite3 ".backup '/var/backups/chio/authority.sqlite3'"
sqlite3 /var/lib/chio/budgets.sqlite3 ".backup '/var/backups/chio/budgets.sqlite3'"
sqlite3 /var/lib/chio/verifier-challenges.sqlite3 ".backup '/var/backups/chio/verifier-challenges.sqlite3'"
sqlite3 /var/lib/chio/edge-sessions.sqlite3 ".backup '/var/backups/chio/edge-sessions.sqlite3'"
```

For witnessed authority custody, also back up the operator key-log database
and enterprise migration database with SQLite `.backup`. Coordinate separate
backups of all witness and auditor databases and preserve the active authority,
operator, artifact-time, and recovery key material through the deployment's
secret-custody system. Treat a pending seed handoff as part of the same atomic
recovery unit as the active seed and operator log.

Back up file-backed registries and policies:

```bash
cp /etc/chio/enterprise-providers.json /var/backups/chio/
cp /etc/chio/verifier-policies.json /var/backups/chio/
cp /etc/chio/certifications.json /var/backups/chio/
cp /etc/chio/*.yaml /var/backups/chio/
cp /etc/chio/mcp-signed-manifest.json /var/backups/chio/
cp /etc/chio/mcp-cage-policy.json /var/backups/chio/
cp /etc/chio/edge-resume-hmac-keyring.json /var/backups/chio/
```

Protect the backup of the HMAC keyring and every keyring seed as secret key
material. Record the binary version, git commit, manifest and cage-policy trust
roots, control authority key set, key-log pin, witness roster, auditor roots,
and session HMAC key versions used for the snapshot.

## 6. Restore Procedure

1. Stop the affected `chio trust serve` or `chio mcp serve-http` process.
2. Restore the SQLite files into the exact paths expected by the service.
3. Restore the file-backed registries, signed launch artifacts, registered trust
   roots, and the exact HMAC keyring backed up with the session database.
4. Restart the process with the same command-line arguments used before the
   incident.
5. Re-run the smoke checks:

   ```bash
   curl -s http://127.0.0.1:8940/health | jq
   curl -s -H "Authorization: Bearer $CHIO_TRUST_SERVICE_TOKEN" \
     http://127.0.0.1:8940/v1/authority | jq
   curl -s -H "Authorization: Bearer $CHIO_ADMIN_TOKEN" \
     http://127.0.0.1:8931/admin/health | jq
   curl -s -H "Authorization: Bearer $CHIO_ADMIN_TOKEN" \
     http://127.0.0.1:8931/admin/sessions | jq
   ```

## 7. Upgrade Procedure

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
   curl -s -H "Authorization: Bearer $CHIO_TRUST_SERVICE_TOKEN" \
     http://127.0.0.1:8940/v1/internal/cluster/status | jq
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

## 8. Rollback Procedure

Rollback is a full binary-and-state rollback to the last known good backup.

1. Stop the candidate processes.
2. Restore the previous binaries.
3. Restore the backed-up SQLite and registry files if the candidate performed
   writes that must be discarded.
4. Restart the previous version with the original arguments.
5. Re-run the same health and admin smoke checks used in the upgrade procedure.
6. Record the failed candidate commit and attach the qualification logs and any
   cluster/admin diagnostics to the incident report.

## 9. Incident Triage Pointers

- Trust-control cluster convergence: check `/health` and
  `/v1/internal/cluster/status`
- Authority rotation or trust drift: check `/v1/authority`
- Remote runtime lifecycle/auth failures: check `/admin/health`,
  `/admin/sessions`, and `/admin/sessions/{session_id}/trust`
- Receipt/export gaps: check `/v1/reports/operator`,
  `/v1/federation/evidence-shares`, and the dashboard summary panels

See [OBSERVABILITY.md](./OBSERVABILITY.md) for the diagnostic contract and the
meaning of the main health/admin fields.
