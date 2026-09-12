# Security roadmap: outcome-based execution plan

Status: accepted for local execution on 2026-09-10. M0 is consolidated and M1 is
in progress. See [current execution status](launch-status.md). On 2026-09-11 the
user authorized committing, pushing and maintaining the accumulated work as a PR,
then continuing implementation. Separate authority is still required for manual
hosted qualification jobs, operator migrations, deployment activation, workflow
repins, publication, merge or promotion.

## 1. Objective and scope

Finish a usable, qualified Chio developer preview, then complete the separately
observed operational promotion. Preserve the complete protocol-primitives,
active-defense and enterprise-hardening requirements. Change execution order and
checkpoint size, not the security contract.

The preview is a Rust library distribution and a confined reference runtime for
one operator with authoritative durable state. The enforced native profile is
Linux x86_64, kernel 6.7 or newer, with every actual cage prerequisite verified.
Automatic response remains disabled in the preview. Portable verification has a
separate qualification record. Distributed-linearizable authority, mobile
hardware qualification, other native sandboxes, customer hosting and unrelated
economic-product expansion remain outside the existing preview contract.

This is an agent/tool mediation kernel, not a claim to ship a bootable operating
system. Public descriptions must identify its trust boundary and supported
execution profiles precisely.

Normative acceptance sources:

- [Protocol primitives](../superpowers/plans/2026-07-09-protocol-primitives.md).
- [Active defense](../superpowers/plans/2026-07-09-security-active-defense.md).
- [Enterprise hardening](../superpowers/plans/2026-07-09-enterprise-hardening.md).
- [Operational promotion](active-defense-rollout.md).
- [Caller dispatch design](../superpowers/specs/2026-09-07-caller-dispatch-commitment-design.md).
- [Historical implementation and evidence ledger](launch-plan.md).

An unavailable required platform, audit, migration or behavioral result is a
blocker for its claim, not permission to delete the requirement. Any proposed
deferral of an accepted feature requires an explicit scope decision.

## 2. Starting point

Working candidate: `/tmp/arc-security-launch`, branch
`security/launch-integration`, HEAD
`8b9f9243905dfa61acac82d83438684940777fe3`.

Before adding this planning document, the candidate had 224 modified tracked
files and 466 untracked files, across 11 classified review slices. These are
accumulated local changes, not 690 changes introduced by the latest fix.
The two existing `/home/connor/backbay` working trees must remain untouched.

Current capture work has executed and passed:

- 44 exact native-policy tests, including 38 post-commit reply/readback fault
  cases and 12 physical-corruption cases inside four new tests.
- Two exact quota/cumulative-accounting tests.
- Exact ledger, egress, attachment, authority-profile, native-authority and
  participant-snapshot groups of 3, 8, 3, 7, 12 and 3 tests respectively.
- 103 kernel admission-operation tests and six SQLite budget-atomicity tests.
- Strict all-target Clippy for kernel, control plane, SQLite and xtask.
- 182 matching source-drift entries and current generated proof coverage.

Counts overlap. They are not a sum of unique tests or formal proofs. The full
96-test adapter run was interrupted and is not passed evidence. Fresh production
feature checks, formal-checker tests, final formatting and the final AST refresh
remain pending for this checkpoint. No Cargo process remains running.

Three material launch gaps are already evidenced:

1. The new native capture checkpoint still denies before connector execution.
2. Caller reserve/execute/report lacks its complete authenticated start and
   durable delivery contract; the lost-report regression remains a counterexample.
3. `examples/reference-swarm` explicitly uses a signed `Disabled` native-launch
   profile. Its task graph is not bound to edge-issued capability identities, and
   per-grant limits are not proof of shared task-pool enforcement.

The three proposed Rust entrypoints currently remain `publish = false`:
`chio-kernel-core`, `chio-kernel` and `chio-swarm-authority`.

## 3. Working rules

### Prioritization

Every new task must do at least one of the following:

1. Fix a demonstrated violation of a supported security invariant.
2. Complete a missing link in a promised end-to-end execution profile.
3. Satisfy an explicit package, compatibility, operational or release gate.

Each task names the violated invariant or acceptance scenario, its owning module,
the smallest appropriate change, its verification and its stopping condition.
Cleanup, abstraction work or extra fault variations without one of these links
go into a separate backlog. A new bypass, secret leak, replay, overspend or
incorrect output release interrupts the queue; cosmetic work does not.

Keep one primary implementation milestone open at a time. Necessary operator
coordination can proceed separately, but no agent delegation is assumed.

### Code quality

- Preserve the existing ownership model, domain ports and dependency direction.
  Do not create another kernel, policy engine, saga framework or quota authority.
- Use validated types, private constructors for verified authority, explicit
  state transitions, checked arithmetic and RAII for owned custody.
- Separate live execution authority from historical evidence. Deserialization,
  a digest, a successful readback or an old receipt cannot mint a new permit.
- Reuse ordinary/nested finalization and canonical codecs. Keep new helpers
  cohesive; do not split files only to move complexity below a line limit.
- Preserve canonical signed bytes, compatibility decisions, fail-closed startup
  and exact owner fencing. No new lint exceptions or relaxed file-size limits.
- Do not make a failing test pass by extending a security deadline, weakening an
  assertion, changing an enforced profile to Disabled or ignoring the test.

### Reporting

Use one short current-status table with milestone, missing acceptance criteria,
next action, blocker and evidence. Keep long logs in the historical ledger and
artifacts. A checkpoint report answers what newly works for a consumer, what was
verified, what remains unsupported and which milestone is next. Test counts and
source-drift entries are evidence, not product-completion metrics.

After two implementation checkpoints without advancing an acceptance scenario,
stop adding refinements and explain the specific blocker and proposed decision.
Reopen a closed boundary only for an affected-input change, a new demonstrated
failure or a required fresh release run. A context reset is not such a reason.
Do not promise a launch date until M1 and M3 have working end-to-end acceptance;
those integration gaps, rather than the number of remaining helper functions,
currently dominate schedule uncertainty.

## 4. Milestones and dependencies

| ID | Outcome | Depends on | Completion evidence |
| --- | --- | --- | --- |
| M0 | Bounded scope, retained evidence and reviewable candidate | Existing work | Requirement map, review-slice index, exact pending work |
| M1 | One complete native secure invocation | M0 | Real ordinary/nested execution, guarded release and signed receipt |
| M2 | Native failure, interruption and restart safety | M1 | Real durable/process cutpoint matrix with invariant-preserving recovery |
| M3 | Correct external caller execution and delivery | M1-M2 | Authenticated start, durable executor claim, lost-report regression passing |
| M4 | No constructor, adapter or SDK bypass | M1-M3 | Complete consumer inventory and positive/negative parity cases |
| M5 | Usable, bound, confined reference swarm | M1-M4 | Real issued-capability/task binding and enforced swarm scenarios |
| M6 | Integrated enterprise boundary | M1-M4; converges with M5 | Keyring, broker, cage and receipts in one real process topology |
| M7 | Active defense complete in dry-run and test profiles | M1-M4 | Flow, deception, correlation, response and rollback contracts |
| M8 | Durable retention and operational recovery | M2-M7 | Retention, scale, migration and recovery evidence |
| M9 | External Rust consumer and packaged runtime | M4-M8 | Packaged dependency closure and clean-environment installation |
| M10 | Exact-candidate developer-preview qualification | M0-M9 | All accepted local, platform, hosted and release gates |
| M11 | Observed pilot and controlled promotion | M10 plus operator authority | Existing numeric window, signed stages and verified rollback |

M5-M7 are convergence milestones, not reasons to reinvent their already-present
components. Their module inventories and operator prerequisites can be prepared
early. Each accepted original requirement must map to one milestone; none may
disappear between the table and the final release checklist.

## M0. Reset execution and consolidate the candidate

1. Preserve the current worktree and stopped-test status. Retain completed logs
   and source fingerprints; mark interrupted and historical results accurately.
   Correct the old ledger's running/active wording when execution resumes.
2. Map every original protocol task, active-defense phase and enterprise phase to
   implemented, locally verified, externally qualified or still missing. Link
   existing evidence; inspect unresolved rows rather than re-reviewing every
   completed helper. Do not invent a completion percentage.
3. Produce a support matrix for ordinary, nested, nonce-required, governed,
   native-flow, brokered and caller-executed calls. Name mandatory participants,
   the public entrypoint, recovery owner, release policy and current limitations.
4. Use `scripts/check-review-slices.py` to prepare dependency-ordered review
   packages for the accumulated changes. Review wire/authority contracts before
   stores, stores before kernel consumers, then adapters, SDKs, runtime and gates.
   Keep cross-layer fixes together when splitting would make an intermediate
   candidate unsafe. Commit/PR creation requires separate authorization.
5. Record the precise pending verification from the capture checkpoint. Do not
   restart its completed 44-test campaign merely because the agent resumes.
   Schedule the unfinished broad checks at the next coherent native milestone;
   until then the checkpoint remains partially qualified.
6. Surface external prerequisites now: qualified Linux runner, registry/package
   ownership, signing/manifest/witness roles, dependency-audit decisions and pilot
   operator. Prepare requests and runbooks without activating external systems.

Exit: a finite launch-blocker list, explicit supported profiles, and a first
review package. No additional capture abstraction or fault enumeration is needed
to satisfy M0.

## M1. Complete the native secure invocation lifecycle

Primary owners: kernel `credential_reservation/native_dispatch.rs`,
`admission_coordinator/native_egress/`, ordinary/nested evaluation, return-context
and finalization modules; control-plane `security/adapters/native_flow*`; SQLite
`admission_operation_store/security_participant_state/` and native capture.

Implement in this order:

1. Complete the existing original authority-profile checks using nonempty runtime,
   governed-approval and DPoP custody together, not just empty or single-participant
   fixtures. Revalidate the actual grant, required original participants,
   delegation, revocation and current runtime evidence.
2. Close the interval between runtime revalidation and physical capture. Bind
   authenticated validity limits and selected artifacts to the transaction-bound
   witness and recheck expiry at the final commit boundary. Do not use an earlier
   successful hook call as unlimited future authorization or call arbitrary hooks
   while holding a mutation mutex.
3. Complete guard, federation and selected economic/supplemental authorization
   before the final dispatch decision. Preserve one authoritative composite hold
   and the original operation. Do not move side effects ahead of durable intent
   to make a context object appear complete.
4. Finish the typed frozen return context with exact participant references,
   admitted evidence, selected grant, stream limits, payment/delivery binding and
   signing identity. Persist only required private context, not reusable secrets.
5. Compose operation-owned native nonce, declassification and flow-use custody
   through the existing authorities. Bind purpose, destination, request and current
   flow generation; consumption is one-shot, and monotone taint cannot be undone
   by compensation. Implement the required supported profiles before removing
   their explicit denials.
6. Connect verified dispatch commitment to the real connector in ordinary and
   nested evaluation through shared helpers. Removing the test checkpoint's deny
   is not the implementation. Production must require the complete live authority.
7. Feed actual results into the existing outcome, output-guard and receipt pipeline.
   Inspect raw output for tripwires before redaction, then enforce flow policy on
   the final delivered representation. Historical accounting authority cannot
   bypass current revocation, containment or output-release policy.
8. Add explicit startup selection and activation checks. Empty databases, missing
   required participants, unsupported backends and mixed legacy/native authority
   configurations refuse startup or dispatch. No automatic populated-store upgrade.

Acceptance: actual ordinary and nested tool calls succeed through the production
path with expected output, one captured invocation and an independently verified
receipt. Removing each required authority or changing a bound input denies before
effect. Blocked output never reaches the caller. The combined nonempty credential
profile works, as do the required nonce/declassification variants. A test-only
hook is not needed to make the successful path reachable.

Stop when the supported lifecycle and named invariants pass. Further internal
factorization requires a concrete correctness or maintainability reason.

M1 checkpoint: the frozen receipt-signing subtask now connects pre-dispatch
selection, private raw return/caller persistence, identity-bound portable signing
and completed replay under retained and current crypto floors. Unfinished output
requires the original signer. Signing callbacks run outside the sequencer and
cannot renew the original finalization lease. Legacy records remain explicitly
unbound, not retroactively upgraded. See the [checkpoint evidence](launch-status.md#frozen-receipt-signing-checkpoint).
The subsequent [native live-owner checkpoint](launch-status.md#native-captured-lifecycle-checkpoint)
connects original capture to one private owner and the frozen return context.
Explicitly opted-in non-nonce/non-declassifying native flows now execute a
registered in-process tool through ordinary and public nested entrypoints,
prepare actual output taint, checkpoint release and return verified receipts.
This does not complete the participant snapshot, required nonce/declassification
variants or confined-process qualification. Those remain required M1 work;
captured historical records cannot reconstruct a lost live owner.

The [participant-reference checkpoint](launch-status.md#frozen-dispatch-participant-reference-checkpoint)
now freezes every pre-dispatch participant reference, including explicit absence,
and binds the native preparation ledger before capture. New private caller v3
frames retain that same selection; legacy frames remain explicitly unbound.
Participant history roots are not fresh claim authority. Required native
nonce/declassification/use custody and confined-process qualification remain
open, as does the external caller's authenticated claim/start contract in M3.

## M2. Qualify native failure and recovery

Build one named cutpoint matrix against real stores and child processes. Reuse
existing fixtures and cutpoint machinery rather than adding a generic fault
framework. Existing reply-fault tests remain useful but do not substitute for
process termination or failure before anchor synchronization.

| Cutpoint | Required disposition |
| --- | --- |
| Before participant acquisition | No effect; no unexplained reservation |
| During reversible reservation | Exact owner-only compensation; replay tombstones retained |
| Before combined capture commits | Entire transaction rolls back |
| Database commit before anchor sync or reply | Unknown remains unknown; reconcile the same operation, never blindly refund or resend |
| After dispatch commit, before connector acceptance | Retain capture unless authenticated non-acceptance satisfies the existing reversal contract |
| After an effect may have started | No fresh execution from retry; preserve unknown outcome and required custody |
| During outcome or receipt persistence | Recover original terminalization without invoking the tool again |
| During output release | No unguarded or duplicated release; retain truthful delivery status |
| After authority restart or owner replacement | Old owner fenced; new owner reconciles original history before readiness |

Exercise the baseline, the combined runtime/approval/DPoP profile, and the
nonce/declassification profiles at their relevant boundaries. Add explicit
revocation-versus-capture, duplicate-start, competing-recovery-worker and late
report races. Do not expand the Cartesian product unless an interaction has a
distinct invariant.

Acceptance: observed effects, quota/cumulative accounting, credential disposition,
operation state and receipts agree at every named cutpoint. No claim of generic
exactly-once network effects: document the downstream idempotency and authenticated
status contract, and retain uncertainty when that contract cannot resolve it.

## M3. Finish authenticated caller start and delivery

Primary owners: kernel `evaluation/caller_execution.rs`, caller context and nonce
coordinators, SQLite caller-context capture/outcome stores, sidecar control routes,
executor adapters and the SDK reserve/execute/report clients.

1. Complete the private durable admission snapshot using M1's actual custody and
   freeze/decoder contracts. A canonical object containing digests is not proof
   that the required participants were retained.
2. Add an authenticated start operation between reservation and external effect.
   Commit the original hold, nonce and required custody before publishing a signed
   authorization bound to request, operation, executor identity/key epoch, attempt,
   validity interval and frozen-context digest.
3. Require the executor to authenticate that authorization and durably claim the
   original attempt before effect. Duplicate delivery must not create a second
   execution. No process-local ownership map or blind redelivery after lost replies.
4. Authenticate delivery reports and reconcile them through the committed context
   into existing finalization. Do not repeat pre-dispatch admission. An expired
   permission may still support historical accounting, never a new execution.
5. Update sidecar routes and SDK clients to the explicit start contract. Old
   reserve-only clients must not silently receive permission to act. Preserve
   canonical schema negotiation and a documented compatibility/migration decision.
6. Convert the existing ignored contract
   `external_delivery::an_external_effect_with_a_lost_report_cannot_be_refunded_at_nonce_expiry`
   into an executed passing regression. Retain its original bad-outcome calibration.
7. Exercise actual executor loss, lost report, nonce expiry, owner restart,
   duplicate delivery, key/attempt substitution, delegated caller shares,
   cumulative approval and monetary/economic custody where supported.

Acceptance: after an external effect and lost report, the invocation remains
captured, a second execution under the exhausted capability is denied, and the
original operation is reconciled or truthfully unknown. A late valid report can
complete it without creating authority for another call.

## M4. Close constructor, protocol and SDK bypasses

1. Reconcile every non-test kernel constructor and each caller/remote dispatch
   entrypoint with the support matrix. Centralized installation must be used, or
   an opted-in unsupported profile must be rejected before authority acquisition.
2. Audit the actual production closure, including CLI wrapping, HTTP authority,
   runtime harness, MCP edges/remote, provider adapters and caller SDKs. Do not
   rebuild every adapter simply because it appears in the crate map.
3. Preserve exact authenticated flow declarations, capability features, aggregate
   budgets, approval sets, DPoP authority, context identities and start/report
   bindings through every affected transformation.
4. Qualify Rust, Python, TypeScript and Go canonical vectors and generated schemas;
   run the existing FFI/C++ consumer gates where their shared boundary changed.
   Include round-trip preservation and deliberate field-drop/substitution cases.
5. Verify that enforced configuration cannot fall back to a legacy constructor,
   direct provider route, ephemeral store or request-supplied authority identity.

Acceptance: every affected entrypoint has an explicit supported-and-tested or
rejected outcome, with no unclassified consumer. Rejection is not completion of
a promised supported feature; any such deferral requires a scope decision.

## M5. Make the reference swarm the launch acceptance program

Extend `examples/reference-swarm` and existing edge/runtime wiring. Preserve the
current Disabled-mode integration smoke under its honest name; add a separately
qualified enforced scenario rather than renaming that smoke as secure deployment.

1. Bind the signed task graph to the actual edge-issued capability identities,
   authenticated workers, delegated scopes and continuation tokens.
2. Install the live task authority in the edges and require swarm admission.
   Enforce the shared task-pool/aggregate budget through the real authority, not
   an orchestrator counter or only per-grant limits.
3. Provision trusted evidence and signed manifests, and launch actual confined
   tools under Enforced mode on the qualified platform.
4. Run success, scope widening, forbidden file/network access, cross-agent data
   leakage, shared-budget contention, continuation replay, worker crash/restart
   and revocation scenarios. Check both caller output and external effects.
5. Export and independently verify receipts, capability/task bindings, accounting,
   enforcement evidence and terminal outcomes as one reproducible run artifact.

Acceptance: a clean documented command runs a real orchestrator and workers
through Chio's complete enforced path; each negative case fails at its owning
boundary. No Disabled fallback, unbound task graph or local accounting substitute
is used as evidence of secure swarm operation.

## M6. Qualify the enterprise controls in that process topology

Reuse `chio-keyring`, `chio-secret-broker`, `chio-cage`, their daemons and the
existing runtime composition. This is composition work, not a new broker product.

1. Verify contiguous key-log synchronization, RFC 6962 consistency, strict-majority
   witnesses, pending/active rotation, fenced signing, trusted artifact time and
   abort/recovery in the configured runtime.
2. Route one provider-backed tool through the encrypted broker custody boundary.
   Register durable intent before budget mutation. Capture the single composite
   parent/aggregate/broker hold with relevant revocation in one commit domain.
3. Prove that raw credentials are absent from the agent, tools, manifests, logs,
   IPC outputs and receipts. A broker failure must not select a direct-provider
   retry. Validate destination, headers/options, proof replay and recovery.
4. Exercise the real cage-init lifecycle: signed manifest and operator ceiling,
   retained descriptors, helper/target identity, Landlock, seccomp, observed exec
   transition and terminal evidence. Missing prerequisites deny launch.
5. Use the designated Linux runner for actual enforcement and migration-canary
   capture. Local aarch64 tests cannot qualify the x86_64 claim.

Acceptance: one production-equivalent invocation demonstrates key verification,
broker custody, shared quota capture, cage enforcement and receipt persistence.
Disabling or corrupting any mandatory boundary denies and produces truthful
failure evidence. Existing enterprise migration stages remain one-way; all
operator activation requires explicit authority.

## M7. Complete active defense without prematurely promoting it

Use the existing flow, deception, temporal, response-authority, overlay and
scheduler implementations. Automatic effects remain disabled in the preview.

1. Verify before-dispatch and before-delivery flow enforcement, complete-source
   taint, unknown-as-Top migration and exact guard/hook order across M4 consumers.
2. Prove canary/watermark denial before effect or delivery, including event-store
   failure and marker/secret redaction across logs and receipts.
3. Qualify deterministic event-time correlation, bounded lateness/eviction health
   and authenticated internal-event provenance. Advisory input cannot authorize
   an executable finding.
4. Complete governed active-response approval through the shared threshold
   verifier and approval-only operation. Bind operator capability, typed governed
   intent and exact fenced affected set; no separate quorum format.
5. Exercise every accepted response action through the dedicated authority and
   durable executor in a controlled test deployment. Cover partial apply/remove,
   overlapping restrictions, stale workers, orphan fences, TTL reordering,
   recovery and truthful rollback-conflict status.
6. Produce signed dry-run plans and executable caught-mutant/conformance evidence.
   Do not mark threat rows closed from registry metadata or source checks alone.

Acceptance: all original active-defense implementation gates pass, response
simulation is correct, and temporary actions use reversible overlays rather than
permanent revocation. Operational promotion remains M11, not an implied outcome
of passing these tests.

## M8. Close retention, scale and operational recovery

1. Resolve the receipt-retention regression tracked as issue #1045 and execute its
   real property. Keep subprocess helper ignores distinct from missing behavior.
2. Run the existing million-receipt scale requirement as a deliberate milestone
   campaign, measuring integrity, recovery, retention, resource use and query
   behavior. Do not substitute a small fixture or metadata validation.
3. Verify that compaction/retention preserves the evidence needed for replay,
   quota/custody reconciliation, output decisions and checkpoint verification.
4. Exercise serving-owner replacement, writer failure, backup/restore and schema
   migration against representative populated stores. Ambiguous legacy effects
   must be reconciled or refused, never backfilled into fabricated safe history.
5. Verify readiness and shutdown ordering: provisioned authority, authenticated
   dependencies, recovery drain, then traffic. Bound exhaustion blocks readiness.
6. Measure hot-path and restart performance against the pre-change baseline and
   existing budgets. Address regressions that threaten supported operation; do
   not turn this into a general benchmarking or optimization project.

Acceptance: required retention/scale tests execute, recovery preserves original
authority and receipts, and operational limits are documented with measurements.

## M9. Package the Rust kernel and reference runtime

1. Review the public entrypoints `chio-kernel-core`, `chio-kernel` and
   `chio-swarm-authority`, including required configuration, stable error types,
   async/blocking behavior, feature boundaries and shutdown semantics.
2. Resolve the complete registry dependency closure and current `publish = false`
   settings deliberately. Do not publish all workspace crates to make dependency
   resolution convenient, or remove safety boundaries to shrink the closure.
3. Build a consumer outside the workspace from the exact packaged artifacts with
   no workspace path patches. Exercise admission, denial, receipts and the
   supported configuration; test the declared MSRV and production feature sets.
4. Package the reference runtime, supervisor, required daemons, manifests and
   provisioning/readiness tooling. Document separate service identities, signing
   and secret custody, supported platforms, recovery and upgrade restrictions.
5. Run clean-environment installation, startup, a successful call, a denied call,
   evidence verification and restart recovery. Preserve no-network/tool-disabled
   defaults except for explicitly configured supported examples.
6. Draft release claims from demonstrated acceptance artifacts. Describe the
   protocol mediation boundary and limitations, not a generic secure-OS or
   exactly-once distributed execution guarantee.

Acceptance: an external developer can consume the packaged API and run the
documented confined reference profile without private repository knowledge or
undocumented local paths. Registry publication remains separately authorized.

## M10. Review, qualify and publish the developer preview

1. Finish dependency-ordered review of the accumulated candidate and new
   milestones. Once authorized, create conventional commits and reviewable PR
   units with the exact invariant, tests and migration impact. No blanket staging
   of unrelated work and no weakening repository protections.
2. Refresh the dependency audit inventory. The historical ledger named 22
   `safe-to-deploy` audit gaps; that number is not assumed current. Complete
   substantive audits or obtain explicitly justified decisions. Do not fabricate
   audits or introduce blanket exemptions to turn the gate green.
3. Run the full final qualification schedule below on an identified source
   candidate. Resolve every failed requirement or explicitly obtain a scope
   decision; do not average green gates into readiness.
4. After authorization, run designated Linux and hosted workflows and reconcile
   exact source/PR/remote SHA, workflow definition, run attempt, terminal checks,
   review findings, generated artifacts and package input hashes.
5. Choose the next unused `0.2.0-alpha.N` through the existing release mechanism.
   Refresh registry state at that time. Build signed evidence and provenance for
   the same artifacts that will actually be published.
6. Publish only after release authorization. Perform clean-install and package
   smoke checks on the published artifacts, and verify their hashes against the
   qualified candidate before announcing availability.

Acceptance: the supported developer preview is review-complete, externally
consumable, exact-candidate qualified and, if authorized, verified as published.
Automatic containment and public/customer hosting are not enabled by this step.

## M11. Observe the pilot and promote separately

Use the existing rollout contract unchanged:

- At least 14 consecutive days and 100,000 mediated invocations, or 30 consecutive
  days for a low-volume cohort. An authority reset restarts the window.
- At least 99 percent reviewed correlation precision across at least 1,000
  reviewed findings. Insufficient real findings leave automatic response dry-run.
- All listed zero-tolerance, unknown-label, recall and rollback requirements.
  Injected tests remain separate from observed workload evidence.
- Signed, cohort-specific stages: dry-run, then qualified throttle/egress
  restrictions, then the separately qualified heavier reversible actions.
- Permanent revocation remains manual. Verify zero active/partial overlays and
  exact restoration before unregistering adapters; retain all signed history.

Acceptance: the evidence window, operator review, selected promotion and rollback
drill are complete. Code completion, preview publication and operational promotion
remain separate records. The full roadmap is not declared complete before its
accepted operational requirements are satisfied.

## 5. Verification schedule

| Stage | Required verification | Avoid |
| --- | --- | --- |
| Editing a boundary | Formatting, focused positive/negative tests, relevant compile/lint and invariant regression | Full overlapping campaigns after every helper or comment |
| Closing a milestone | Affected crates and consumers, integration/cutpoint matrix, all-target lint, schema/model drift checks where changed, final AST update after code changes | Calling partial or filtered-zero output a gate pass |
| Freezing the release | Complete original roadmap, workspace, dependency, formal, platform, packaging and hosted gates | Reusing stale evidence for a changed input closure |

For unchanged source, preserve completed evidence across interruptions. If a
broader suite covers the same tests, report that suite rather than rerunning a
subset only to add another result count. Do not claim an existing exact gate ran
when it did not. Required published gate scripts still execute at release; any
future evidence-reuse mechanism must validate exact inputs and test identities.

Local Rust execution keeps the established Rust 1.94.1 locked/offline setup,
`umask 022`, disabled incremental compilation/core dumps, one test thread and
serial Cargo processes. The declared MSRV and cross-platform builds are additional
qualification, not replaced by the local toolchain. Do not run graph refreshes
alongside timing-sensitive tests.

Final qualification retains these existing gates and their prerequisites:

- Workspace build, tests, strict Clippy, formatting and `git diff --check`.
- Schema registry, canonical vectors and four-language `make codegen-check`.
- Protocol concurrency, required Kani harnesses, mapping, applicable Lean/TLA/
  Apalache/formal campaigns and source-drift checks. Hash matching is not a proof.
- `check-flow-security.sh`, `check-deception-security.sh`,
  `check-temporal-security.sh`, `check-response-recovery.sh` and adversarial gates.
- `check-keyring-transparency.sh`, `check-secret-broker-boundary.sh` and actual
  `check-cage-enforcement.sh` on the designated platform.
- Provenance, dependency direction, `cargo deny`, refreshed `cargo vet`, source
  hygiene, public/package surface, review-slice and CI contract checks.
- Retention/scale, external-consumer/SDK and release-input qualification, followed
  by the existing authorized exact-candidate release workflow.

Known ignored tests must be classified individually: missing seam, separately
executed process helper, optional artifact, or release-only scale campaign.
None is evidence of a property merely because the surrounding suite is green.

## 6. Immediate next execution steps

The original dependency order is retained below. M0's maps and the first successful
ordinary/nested native in-process lifecycle are now implemented. The current M1
frontier is the required nonce/declassification/flow-use profiles and confinement
qualification. Frozen participant references are bound. Native strict-nonce
preflight now has separate operation-owned taint custody; it does not satisfy the
dispatch join or authorize capture. The next nonce slice must bind actual issued
material through fresh dispatch preparation, capture and ordinary/nested release.

1. Complete M0's support/requirement and review-slice maps, preserving the stopped
   capture checkpoint without rerunning its completed tests.
2. Define M1's real successful ordinary/nested native invocation acceptance test
   using the existing kernel, store, resolver and tool harness. Expose the precise
   first missing lifecycle link; do not create another capture-only observer.
3. Complete combined credential freshness and the frozen return-context ownership
   needed by that invocation. Then compose nonce/declassification and real dispatch,
   output release and terminal receipts in the specified order.
4. Close M1 with one affected-surface qualification and graph refresh; execute M2's
   bounded real crash/recovery matrix next.
5. Proceed to the caller lost-report contract, consumer wiring and enforced
   reference-swarm acceptance. Keep operator prerequisites visible from M0 onward.

Do not restart open-ended repository cleanup, add new frameworks, or add another
round of capture metadata fault variants without a demonstrated missing invariant.
At every milestone boundary, reassess this order against the actual remaining
launch blockers and report any proposed scope change before taking it.
