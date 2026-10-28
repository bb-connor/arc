# Active Defense Rollout Contract

This document is the operator contract for moving Chio active defense from disabled to shadow and then to enforced operation. A deployment must meet every gate for its current stage before advancing. A missing measurement, skipped probe, or unavailable durable authority blocks promotion.

The shipped boundary is dark and component-scoped. Chio includes the portable
security types, durable stores, key-log runtime, secret-broker daemon, cage
launcher, active-response authority protocol and dedicated listener daemon,
migration verifier, and evidence gates. It does not include the removed
historical broker-product composition, an implicitly combined broker and
response-authority deployment, a provider deployment, or authorization for
public or customer traffic. The procedures below are promotion requirements,
not claims that those operational stages have run.

## Fixed invariants

- Only signed `chio.manifest.v1` manifests may opt into flow enforcement.
- Every constructor serving an opted-in tool installs one complete `SecurityRuntime` authority bundle atomically.
- Unknown historical information is `Top`. It is never inferred as `Bottom`.
- Principal and capability-lineage taint survives closure of a session that predates enablement. Only a verified isolation-epoch transition starts an isolated successor.
- Only verified internal security events may produce an automatic-response finding.
- Truncated causal scope, an unavailable authority, an unverified receipt, or an incomplete rollback denies automatic promotion.
- Once a tool, provider, or server is marked enforced, an operational failure denies service. It never falls back to unenforced service.
- Permanent revocation remains manual.

## Inventory and migration report

Before shadow mode, run the Chio security migration command against every registered manifest and adapter. Retain its signed report with the release evidence. The report must contain:

- manifest identity, signer, canonical digest, and migration outcome;
- every effective-egress tool without a policy-owned destination clearance;
- every tool with an unknown output declaration or an invalid purpose set;
- every adapter that cannot preserve the exact flow declaration and authenticated security extensions;
- every direct credential environment or file grant that must move behind the secret broker;
- every native server selected for cage enforcement and its independent operator ceiling;
- every pre-enablement principal, lineage, and session record, each assigned `Top`;
- every manifest requiring operator re-signing.

The report passes only when unsupported adapters and undeclared effective egress are zero for the proposed enforcement cohort. Migration never signs on behalf of an operator.

Run the command with one closed JSON inventory and a destination on the same filesystem as its temporary file:

```bash
chio security shadow-migrate \
  --input active-defense-inventory.json \
  --output active-defense-migration-report.json
```

The input schema identifier is `chio.active-defense.shadow-migration-input.v1`. Its top-level fields are `manifest_public_keys`, `manifests`, `backfill_targets`, and `shadow_observations`. Every nested object is closed. Duplicate JSON members, unknown fields, unsafe JSON numbers, duplicate key identities, duplicate registry identities, and incomplete per-tool deployment inventories reject the complete input.

Each manifest entry contains:

- one registry identity and the identity of its independently registered Ed25519 public key;
- the original envelope fields `manifest`, `signature`, and `signer_key`;
- exactly one deployment record for every tool in the signed body, including runtime egress, policy-owned clearances and purposes, adapter preservation results, and direct credential grants;
- either a managed runtime declaration or a native runtime declaration with its independently supplied cage ceiling;

The verifier refuses any body whose schema id is not `chio.manifest.v1`, then parses the body as the closed normative type, so an older shape carrying that id is refused by structure. The parsed manifest is verified against the registered key through the manifest verifier. The command has no conversion path and no signing input.

Every backfill target is assigned `Top`, and so is the durable record of each principal and lineage that a target names.

The report is canonical JSON written by file synchronization plus atomic rename. No output file is changed until the complete input and every manifest verify. The report emits these metric names without embedding promotion thresholds:

- `chio_active_defense_shadow_unknown_labels_total`
- `chio_active_defense_shadow_store_errors_total`
- `chio_active_defense_shadow_late_events_total`
- `chio_active_defense_shadow_state_evictions_total`
- `chio_active_defense_shadow_decoy_touches_total`
- `chio_active_defense_shadow_lineage_truncation_total`
- `chio_active_defense_shadow_proposed_effects_total`
- `chio_active_defense_shadow_rollback_simulation_total`
- `chio_active_defense_shadow_false_positive_review_total`

## Shadow evidence window

Each proposed tenant cohort must complete at least 14 consecutive days and 100,000 mediated invocations in shadow mode. Low-volume cohorts that cannot reach the invocation minimum must instead complete 30 consecutive days. Any authority reset restarts the window.

Promotion requires all of the following over the complete window:

| Signal | Required result |
|---|---|
| Unsigned or stale manifest accepted | 0 |
| Adapter declaration loss or mutation | 0 |
| Security store error hidden from evidence | 0 |
| Simulated fail-closed case incorrectly allowed | 0 |
| Unknown label after completed verified backfill | no more than 1 per 10,000 invocations, with every instance reviewed |
| Late event outside the configured bound entering a match | 0 |
| Correlation state eviction without detector-health evidence | 0 |
| Untrusted or advisory event producing an executable finding | 0 |
| Truncated lineage producing an executable plan | 0 |
| Production decoy false positive | 0 |
| Seeded canary reaching a fake tool server | 0 |
| Reviewed correlation precision | at least 99 percent across at least 1,000 reviewed findings |
| Injected attack-sequence recall | 100 percent across every registered conformance and adversarial case |
| Response simulation double apply or double remove | 0 |
| Response simulation ending `lifted` with a remaining reversible contribution | 0 |
| Rollback conflict reported as clean lift | 0 |
| Receipt body contradicting durable state | 0 |

The reviewed-finding minimum is not waived for an automatic-response cohort. A cohort without enough findings remains dry-run.

## Promotion sequence

1. Enforce flow only for tools with explicit `flow_v1` policy, signed `chio.manifest.v1` manifests, and an atomically installed production runtime.
2. Reject every newly registered effective-egress tool that lacks its complete declaration.
3. Arm tenant-specific production decoys after confirming that development markers and keys are absent.
4. Enable signed dry-run response plans. Approval, capability, causal-scope, receipt, and rollback checks still execute, but no external effect is applied.
5. Enable `ThrottleSession` and `RestrictEgress` only after their overlap, stale-fence, restart, out-of-order expiry, and store-outage gates pass.
6. Enable `SuspendSession`, `SuspendCapabilitySet`, and `FreezeIssuance` only after the full crash matrix, exact restore, orphan-fence recovery, and operator-page paths pass on production-equivalent durable stores.
7. Keep permanent revocation manual.

Every stage requires a new signed release record naming the cohort, policy hash, manifest set hash, rule set hash, classifier hash, runtime build, evidence window, and exact gate results.

## Production response authority

The active-response protocol in `chio-control-plane`, the
`chio-active-response-authorityd` runtime, and the
`chio-secret-brokerd.runtime-config.v1` broker daemon are boundaries that must
be qualified independently. A combined deployment uses the closed
`chio.active-defense.deployment-config.v1` schema and validates its digest with
`chio security authority-deployment validate` before it may enter this
section's promotion sequence. There is no implicit same-process composition.

The deployment requires `responseAuthority.responseExecutionMode` to be
`dry_run` or `live`; the runtime subset uses
`chio.active-response-authority.runtime-config.v1`. Both schema identifiers and
the execution mode participate in the deployment digest. Missing or unknown
modes and mode changes under a retained digest are rejected.

- Run the response authority as a dedicated Unix process. Its socket path, PID, UID, and GID are pinned exactly. The socket directory and socket must be owned by the pinned UID and must not be group- or world-writable.
- The authority daemon accepts only the complete canonical combined deployment as its `--config` input and validates the normalized deployment digest before extracting its runtime projection. A standalone response-authority subset cannot start the daemon. It then owns a `chio-secure-ipc` listener, retains an exclusive lifecycle lock, refuses an unknown preexisting node, binds the exact path, sets mode `0600`, authenticates kernel peer credentials before parsing bytes, rechecks the retained socket inode, and unlinks only that inode during shutdown. The protocol server remains independent of socket lifecycle ownership.
- The response-authority socket must not alias the broker authority socket, broker client socket, any security database, or any alert archive. The response-authority PID must differ from the broker authority PID.
- Pin one response-authority signing key and one dedicated active-defense executor/client signing key in the deployment's closed configuration. Load each private key from its own sealed inherited descriptor. The client key must match the response authority's exact trusted client. Both keys must differ from broker, capability-issuer, release-receipt, manifest, and governed-admin keys, and from each other. Runtime signer rotation requires a new validated configuration and process restart.
- Configure stable, globally unique lease-owner identities for each live executor and scheduler worker. They must differ from one another; a shared signing key is not a lease-owner identity.
- Plan policy and artifact snapshots offline with `chio security authority-store digest`, then bind that content digest into the combined deployment and run `chio security authority-deployment digest`. After populating and validating both deployment digest fields, build the final snapshot with `chio security authority-store build`. These explicit phases avoid a store-to-deployment bootstrap cycle. The build command requires canonical `chio.active-response-authority.bundle.v1` input, creates new mode `0600` database and manifest files without overwrite, and commits a logical digest over sorted canonical records. The daemon opens the snapshot read-only with no-follow semantics, recomputes the logical digest, validates every lookup key and record, and serves decisions only from that verified in-memory image. The retained database is used for custody and health revalidation. A store, deployment, authority, or record-count mismatch fails closed.
- Every v2 request and response uses canonical bounded framing, exact peer credentials, signatures, freshness, replay protection, deployment and store digests, and one absolute deadline covering connect, write, and read. Version 1 is retired and rejected. Non-Linux production startup fails closed.
- The daemon uses a fixed worker pool and bounded accept queue. Malformed or unauthenticated clients are isolated as nonfatal peer faults. Store corruption, signer drift, poisoned synchronization, and response-invariant failures terminate the runtime for supervisor restart.
- `SelectPolicy` returns an opaque `AdmissionArtifactRef`. `LoadArtifacts` returns the complete signed bundle. The authority attests the submitter proof and exact artifact payload. The broker persists a write-once canonical bundle digest before kernel preparation. A changed proof, token order, payload, authority, or reference is equivocation and blocks recovery.
- Startup order is signed authority health, parked active-defense host, dedicated response-kernel bind, synchronous durable recovery drain, full readiness, then product traffic. A missing listener, failed peer check, failed signature, or unhealthy authority blocks startup before host publication and traffic. Recovery stops startup when its per-pass record bound, total record bound, or wall-clock bound is exhausted. A restart repeats the complete drain before accepting traffic.
- Receipt correlation remains disabled unless a future closed runtime schema pins explicit receipt producers. A configuration that enables it without those producers is rejected.

## Enterprise hardening sequence

Each enterprise control is registered enforced in the ledger before the
process that depends on it publishes traffic. A provider-backed native server
serves only when all of its controls are registered:

1. Synchronize complete contiguous key-log checkpoints and operate a strict-majority witness roster plus two independently keyed audit monitors before registering key-log verification.
2. Complete witnessed rotation activation and abort recovery before a rotated key signs.
3. Register broker credential custody once the credential is provisioned through the encrypted broker backend; the broker never releases raw credential material.
4. Register broker quota enforcement with the shared parent, aggregate, and broker-capability quota hold and crash reconciliation in place.
5. Register cage enforcement per tool server from its sealed cage plan and retained descriptor table, verified through the isolated ephemeral Linux x86_64 capture, one signed manifest at a time.

The enforcement ledger is `SqliteEnterpriseMigrationStateStore`. Each
deployment, provider, or tool-server control holds exactly one signed
registration that pins the posture of its enforced contract. The database
rejects a second registration for the same control, updates, and deletion.
Key-log controls are deployment-scoped, broker custody and quota controls are
provider-scoped, and cage controls are tool-server-scoped. The signed policy or
configuration that names a control pins the registration digest as its head,
so a replaced or restored ledger cannot satisfy it. Changing an enforced
contract requires a new ledger and a newly pinned head.

Every production process must load an exact
`EnterpriseMigrationRuntimeBinding` before publishing traffic. A configured
posture that differs from the registered posture blocks startup, and every
protected operation revalidates the retained registration, so a replaced or
changed ledger denies until the process is rebuilt.

Repository mechanics evidence has four trust domains. The default-branch
`pull_request_target` controller revalidates the owner, actor, workflow and run
identity, live pull-request base and head, exact test merge tree, label state,
and `CHIO_AUTHORIZED_SECURITY_SOURCE_SHA`. The only permitted source is that
commit or a linear descendant whose commits change only the exact three-file
committed evidence surface. The default-branch capture repeats those checks,
then executes the exact merge on ephemeral GitHub-hosted Ubuntu 24.04 with
persisted checkout credentials disabled and no repository secret. It emits
canonical `chio.enterprise-linux-capture.v2` data and an exact checksum
manifest.

After enforcement upload, a no-checkout capture job explicitly dispatches the
exact default-branch finalizer definition. The finalizer polls that exact
capture run to completion, then binds the controller, capture, and finalizer
workflow IDs, paths, definition commit, actors, run IDs and attempts. It also
binds the runner job, reserved GitHub-hosted runner group, exact runner labels,
live merge tree and labels, artifact ID, digest, compressed size, timestamps,
and issuance window before downloading. Archive
extraction rejects extra or duplicate members, path traversal, links,
non-regular files, excessive compression, and individual or aggregate size
overflow. Candidate data is reduced to validated fixed-shape identifiers and
digests before the protected signing job begins.

Only one step in the `enterprise-evidence-signing` environment receives the
mechanics seed. The public key is a repository variable. A trusted
`chio-enterprise-evidence` binary is downloaded from the repository release URL
and must match the repository-variable SHA-256 before the secret-bearing step
can start. The step creates and immediately verifies only:

```text
enterprise-migration-canary.json
enterprise-migration-canary.json.sha256
enterprise-migration-binding-digest.txt
```

There is no detached custom workflow envelope. The signed artifact is the
canonical `chio.enterprise-migration-canary-evidence.v1` surface consumed by
`verify-committed-linux-evidence`. It fixes repository mechanics only and
cannot assert that production traffic ran or that cutover was authorized.

The fourth domain publishes the merge authority. A secret-free finalizer job
requires the configured committed evidence SHA to equal the live pull-request
head, verifies that commit with checker bytes from the authorized source, and
authenticates the exact current `ci.yml` run plus the four ordinary CI jobs and
the Actions security aggregate. It seals those results with every validated
controller, capture, runner, artifact, and evidence binding. A separate
main-branch job in the `security-check-publisher` environment then mints a
short-lived token for the private `chio-security-authority` GitHub App and
revalidates the live test merge `M`, posts four App `15368` mirrors of the
ordinary checks on `M`, and posts `Security contract` on `M`. The five contexts
share `(<PR>, <E>, <M>, <S>)`; only `Security contract` is pinned to the
dedicated App. A default-branch failure-only `workflow_run` listener converts
all five namespaces to sticky failure after a later failed, cancelled, or
timed-out CI rerun on the same PR/E/M. Capture labels have no publication or
revocation authority after capture.
Workflow YAML does not provision the App, environment, secret, or ruleset.

The controller, capture, and finalizer definitions must already exist on the
default branch. The pull request that introduces them cannot create trusted
controller or finalizer evidence from its own workflow revision.

## Rollback sequence

Rollback is fail-closed and preserves evidence:

1. Stop admission of new response plans and stop correlation consumption.
2. Allow the durable scheduler to lift active reversible effects, or submit an explicitly authorized lift.
3. Query durable response and overlay stores until active, expiring, applying, rolling-back, and rollback-partial records for the cohort are zero.
4. Resolve every rollback conflict and verify the external target against its recorded resulting-version hash.
5. Unregister runtime adapters only after the zero-active check succeeds.
6. Retain signed receipts, taint, verified and advisory events, decoy lifecycle records, response history, key-log history, broker attempt history, and cage terminal evidence.

Disabling new planning never deletes or weakens an existing containment contribution. A rollback that cannot prove clean restoration remains restrictive and pages an operator.

## Release evidence

The release record must include the exact commit, generated-schema manifest hashes, conformance and adversarial manifest hashes, formal proof manifest, Kani and loom results, Apalache results, unsigned Linux cage capture, hosted runner and workflow run identities, default-branch workflow-definition commit, receipt-log checkpoint, and the full workspace build, test, clippy, formatting, dependency, and code-generation results. Unsupported, skipped, ignored, filtered-to-zero, or unavailable results do not count.
