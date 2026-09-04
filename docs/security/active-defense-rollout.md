# Active Defense Rollout Contract

This document is the operator contract for moving Chio active defense from disabled to shadow and then to enforced operation. A deployment must meet every gate for its current stage before advancing. A missing measurement, skipped probe, or unavailable durable authority blocks promotion.

The shipped boundary is dark and component-scoped. Chio includes the portable
security types, durable stores, key-log runtime, secret-broker daemon, cage
launcher, active-response authority protocol, migration verifier, and evidence
gates. It does not include the removed historical broker-product composition,
an operator-owned response-authority listener daemon, a provider deployment, or
authorization for public or customer traffic. The procedures below are
promotion requirements, not claims that those operational stages have run.

## Fixed invariants

- Only re-signed `chio.manifest.v2` manifests may opt into flow enforcement.
- Every constructor serving an opted-in tool installs one complete `SecurityRuntime` authority bundle atomically.
- Unknown historical information is `Top`. It is never inferred as `Bottom`.
- Principal and capability-lineage taint survives legacy session closure. Only a verified isolation-epoch transition starts an isolated successor.
- Only verified internal security events may produce an automatic-response finding.
- Truncated causal scope, an unavailable authority, an unverified receipt, or an incomplete rollback denies automatic promotion.
- Once a tool, provider, or server is marked enforced, an operational failure denies service. It never selects the legacy path.
- Permanent revocation remains manual.

## Inventory and migration report

Before shadow mode, run the Chio security migration command against every registered manifest and adapter. Retain its signed report with the release evidence. The report must contain:

- manifest identity, signer, canonical v1 or v2 digest, and migration outcome;
- every effective-egress tool without a policy-owned destination clearance;
- every tool with an unknown output declaration or an invalid purpose set;
- every adapter that cannot preserve the exact flow declaration and authenticated security extensions;
- every direct credential environment or file grant that must move behind the secret broker;
- every native server selected for cage enforcement and its independent operator ceiling;
- counts of principal, lineage, and session records backfilled from verified receipts;
- counts assigned `Top` because verified evidence was absent;
- every manifest requiring operator re-signing.

The report passes only when unsupported adapters and undeclared effective egress are zero for the proposed enforcement cohort. Migration never signs on behalf of an operator.

Run the command with one closed JSON inventory and a destination on the same filesystem as its temporary file:

```bash
chio security shadow-migrate \
  --input active-defense-inventory.json \
  --output active-defense-migration-report.json
```

The input schema identifier is `chio.active-defense.shadow-migration-input.v1`. Its top-level fields are `manifest_public_keys`, `receipt_public_keys`, `manifests`, `backfill_targets`, `backfill_receipts`, and `shadow_observations`. Every nested object is closed. Duplicate JSON members, unknown fields, unsafe JSON numbers, duplicate key identities, duplicate registry identities, and incomplete per-tool deployment inventories reject the complete input.

Each manifest entry contains:

- one registry identity and the identity of its independently registered Ed25519 public key;
- the original envelope fields `manifest`, `signature`, and `signer_key`;
- exactly one deployment record for every tool in the signed body, including runtime egress, policy-owned clearances and purposes, adapter preservation results, and direct credential grants;
- either a managed runtime declaration or a native runtime declaration with its independently supplied cage ceiling;
- for a legacy permission shape only, explicit destination ports and the selected closed syscall profile.

The verifier checks the original signature before decoding or converting the manifest. A signed v2 body is parsed as the strict normative type and verified again through the manifest verifier. A signed v1 body is verified as its original canonical body, converted deterministically, and emitted only as an unsigned v2 artifact. The command has no signing input and never emits a signature for a converted artifact. Every converted artifact carries its source digest, unsigned v2 digest, and `operator_resigning_required=true`.

Backfill evidence is accepted only from the signed receipt metadata member `active_defense_backfill_v1`, whose schema is `chio.active-defense.backfill-evidence.v1`. The receipt key must match a registered receipt key, the receipt signature and parameter hash must verify, and the evidence must name the exact digest of a registered, successfully verified signed v2 manifest containing the receipt's server and tool. A converted unsigned v2 artifact cannot authorize backfill. A target without that evidence is assigned `Top`. If any inventoried legacy session for a principal or lineage lacks evidence, the durable principal or lineage record is also assigned `Top`, including when another signed receipt says that a legacy session closed.

The report is canonical JSON written by file synchronization plus atomic rename. No output file is changed until the complete input, every manifest, and every backfill receipt verifies. The report emits these metric names without embedding promotion thresholds:

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

1. Enforce flow only for tools with explicit `flow_v1` policy, re-signed v2 manifests, and an atomically installed production runtime.
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
`chio-secret-brokerd.runtime-config.v5` broker daemon are boundaries that must
be qualified independently. A combined deployment uses the closed
`chio.active-defense.deployment-config.v1` schema and validates its digest with
`chio security authority-deployment validate` before it may enter this
section's promotion sequence. There is no implicit same-process or legacy
composition.

- Run the response authority as a dedicated Unix process. Its socket path, PID, UID, and GID are pinned exactly. The socket directory and socket must be owned by the pinned UID and must not be group- or world-writable.
- The authority daemon owns a `chio-secure-ipc` listener. It retains an exclusive lifecycle lock, refuses an unknown preexisting node, binds the exact path, sets mode `0600`, authenticates kernel peer credentials before parsing bytes, rechecks the retained socket inode, and unlinks only that inode during shutdown. The protocol server remains independent of socket lifecycle ownership.
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

Enterprise controls advance independently and converge before a provider-backed native server becomes fully enforced:

1. Publish shadow key-log checkpoints, synchronize complete contiguous logs, and operate a strict-majority witness roster plus two independently keyed audit monitors.
2. Complete witnessed rotation activation and abort recovery before enforcing the new key.
3. Provision one credential through the encrypted broker backend and compare audit-only requests without releasing raw credential material.
4. Enable the shared parent, aggregate, broker-capability quota hold and crash reconciliation before removing direct credential access.
5. Compile sealed cage plans and retained descriptor tables in observation mode.
6. Enforce cage-init for a canary server through the isolated ephemeral Linux x86_64 capture, then expand one signed manifest at a time.
7. Enforce key-log pins only after witnessed continuity and trusted artifact-time checks pass.
8. Delete legacy secret and launcher configuration only after all dependents are enforced.

The one-way stage authority is `SqliteEnterpriseMigrationStateStore`. Register
each deployment, provider, or tool-server control at `disabled`, then advance it
with generation-checked compare-and-swap through `shadow`, `enforced`, and
`legacy_removed`. The database rejects skipped stages, reverse updates,
identity rebinding, stale generations, and deletion. Key-log controls are
deployment-scoped, broker custody and quota controls are provider-scoped, and
cage controls are tool-server-scoped.

Every production process must load an exact
`EnterpriseMigrationRuntimeBinding` before publishing traffic. A configured
stage below durable state is a downgrade attempt. A configured stage above
durable state is an uncommitted advance. A configuration digest mismatch is a
rebind attempt. All three block startup. At `enforced` and `legacy_removed`,
the binding returns `Deny` for operational failure and the caller must not
select a legacy credential, verifier, quota, or launcher path.

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

The migration canary is the
`chio.enterprise-migration-canary-evidence.v1` artifact. Its
signed body fixes `repository_mechanics_only=true`, both production attestation
fields to `false`, and `operator_attestation_required=true`. It binds the
durable `shadow` generation for every proposed control and is governance input
for the separate Shadow-to-Enforced promotion decision. The workflow first
invokes `verify-committed-linux-evidence` with independently supplied source,
runner, configuration, inventory, gate, binding, public-key, and freshness
expectations. After the three files are committed as an evidence-only linear
descendant, `scripts/check-committed-linux-evidence.py` additionally verifies
the Git ancestry, exact tree modes, clean checkout, pinned verifier digest, and
the same semantic expectations. The reusable enterprise lane runs those checker
bytes from the exact `CHIO_AUTHORIZED_SECURITY_SOURCE_SHA` checkout in a fresh
job against the detached `CHIO_COMMITTED_LINUX_EVIDENCE_SHA`; it does not run
the candidate tree's checker. A separate no-checkout binding job fixes the
source input to the event head, while the ordinary enterprise jobs exercise the
event test commit (the pull-request synthetic merge or pushed commit). Neither
verifier produces a cutover verdict.

Production cutover evidence uses the distinct
`chio.enterprise-migration-cutover-attestation.v1` signature domain. Verify it
with an independently pinned operator public key and the exact retained canary:

```bash
chio-enterprise-evidence verify-cutover \
  --canary enterprise-migration-canary.json \
  --attestation enterprise-migration-cutover-attestation.json \
  --runner-public-key "$PINNED_RUNNER_PUBLIC_KEY" \
  --operator-public-key "$PINNED_OPERATOR_PUBLIC_KEY"
```

Verification fails if either signature is invalid, if the operator key is not
the pinned key, if any commit, runner, configuration, inventory, durable state,
generation, or gate digest differs. The operator attestation binds the exact
pre-promotion canary and each exact `enforced` generation observed after
production traffic. It also binds the digest of the separate governance
authorization that promoted Shadow to Enforced. It fixes
`authorizes_shadow_to_enforced=false` and can only authorize the subsequent
Enforced-to-LegacyRemoved transition. The operator signature is the only
artifact that can assert observed production traffic and completed cutover.

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

The release record must include the exact commit, generated-schema manifest hashes, conformance and adversarial manifest hashes, formal proof manifest, Kani and loom results, Apalache results, unsigned Linux cage capture, committed migration-canary evidence, hosted runner and workflow run identities, default-branch workflow-definition commit, receipt-log checkpoint, and the full workspace build, test, clippy, formatting, dependency, and code-generation results. Unsupported, skipped, ignored, filtered-to-zero, or unavailable results do not count.
