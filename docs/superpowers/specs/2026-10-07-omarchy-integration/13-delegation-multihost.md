# Delegated workers and multiple hosts

Status: Proposed, later-stage P6 scope.

Confidence: high for the inspected native attenuation/process contracts and Pi facade gaps; moderate for this proposed deployment design; unknown for Omarchy multihost runtime qualification. Basis: direct inspection of NQ-CANDIDATE and the pinned public Pi adapter, mapped in [readiness](research/chio-readiness.md).

Scope: task trees, bounded child admission, worker ownership, native original-operation recovery and optional cross-host execution or stopped-state relocation. Dependencies: P3 exact approvals, the host adapter, confinement, durable lifecycle/recovery, receipt verification and separately qualified native child services. P6 is not enabled merely by installing Pi or completing P2. No implementation or release is asserted here.

## Decision and alternatives

Use one selected Chio authority and its durable process runtime to admit every worker and effect in a task tree. The desktop presents parentage, budgets and outcomes. The native process host owns child admission and approved launch templates; the desktop controller does not mint capabilities, hold child signing keys or maintain a second dispatch/recovery authority.

Start P6 with confined local children using a small fixed template catalog. Optional remote-worker and stopped-host-relocation profiles need their own custody and platform gates. A worker may reason with a different qualified host or model, but that does not change its Chio authority or grant it broader tools.

Reject three shortcuts: giving every worker the root credential, treating filtered tool names as delegation, and letting an agent pass arbitrary executable/argv/container/SSH selectors to a launcher. All three bypass the selected child authority or confinement boundary. A general distributed scheduler, live authority migration and disconnected offline execution are outside the initial profile.

## Existing source and missing delivery

NQ-CANDIDATE's `ProcessRuntime::open` requires durable admission for all calls and a qualified store. Its `create_root` retains immutable capability and tree limits. `spawn` validates exactly one signed delegation hop from the parent, the same issuer/budget family, narrowed scope/validity and bounded share. `invoke` reserves one tree logical-call slot and dispatches or recovers through the existing kernel. The process registry cannot execute tools or reconcile kernel admission itself.

`ProcessRegistry::submit_child` retains request binding, generated child identity, parent, capability, private signer, template, input and share transactionally. The process-host lifecycle service exposes selected `spawn_<template>`, `wait_children` and `settle_children` tools only for an active native run. Its serving-only configuration leaves delegation disabled. Those process/cage/session-credential surfaces are absent from the inspected main trees; see NQ-01 through NQ-05 in the source crosswalk.

Pi's public `submitNativeChild` is a composition contract around installed native handles. Its process-local submission set is not a durable distributed queue. `NativeChildPort` requires a delivered native implementation for `submit`, `reconcile`, `cancel` and optional `wait`. The bundled bridge's attenuation operation is unsupported. Issuing a narrower transport credential for an existing retained session neither creates a child process nor clears an uncertain outcome. Complete facade callbacks still require native qualification.

Candidate process state export/import is a stopped-host operation that retires and seals the old authority location, verifies complete file identities and reanchors retained state. It is not simultaneous serving or live migration. This specification requires the delivered cross-host profile to prove that the original authority/custody rules still hold; a copy command by itself is insufficient.

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| OM-DLG-001 | Delegation MUST remain unavailable until P3 and exact native process/child/confinement prerequisites pass; Pi callback or package availability alone MUST NOT enable it. | AT-DLG-001 |
| OM-DLG-002 | Every child MUST descend from one retained parent under the selected authority through verified signed attenuation; issuer, scope, validity, budget family and target bindings MUST remain constrained. | AT-DLG-002 |
| OM-DLG-003 | Child admission MUST atomically retain original request identity, exact template/input binding, capability and signer custody before launch; duplicate requests MUST replay original admission or conflict. | AT-DLG-003 |
| OM-DLG-004 | Workers MUST use operator-installed immutable templates and independently qualified guest confinement; child input MUST NOT choose executable, argv, environment, packages, sockets or authority. | AT-DLG-004 |
| OM-DLG-005 | Root and subtree limits MUST cover admitted processes, depth, concurrency, logical calls, provider usage and wall/expiry bounds; sibling reservations MUST fit their parent without implicit reclamation. | AT-DLG-005 |
| OM-DLG-006 | Expiry, revocation and cancellation MUST fence new admission at the native linearization point; previously admitted effects and surviving processes MUST retain truthful independent status. | AT-DLG-006 |
| OM-DLG-007 | Every logical effect MUST retain its original native identity, exact request/authority binding and admission history across worker crash, host change and result delivery. | AT-DLG-007 |
| OM-DLG-008 | Each active worker and authoritative state writer MUST have one verifiable owner with fenced generation/lease; timeout or stale PID alone MUST NOT authorize takeover or effect repetition. | AT-DLG-008 |
| OM-DLG-009 | Cross-host communication MUST authenticate host/worker/authority and restrict routes, disclose only admitted context and retain exact dependency/artifact identities; raw host-control sockets MUST remain inaccessible. | AT-DLG-009 |
| OM-DLG-010 | Handoff or relocation MUST transfer complete required custody and original records through a native-supported protocol; the source MUST be retired/fenced before destination authority can serve. | AT-DLG-010 |
| OM-DLG-011 | Unknown remote effects MUST remain unresolved until native/provider-owned original evidence permits reconciliation; no arbitrary exactly-once external-effect guarantee or blind retry is permitted. | AT-DLG-011 |
| OM-DLG-012 | Child results MUST pass native receipt/result and disclosure verification before parent ingestion or ACK; a child success claim, message or checkpoint MUST NOT authorize another effect. | AT-DLG-012 |
| OM-DLG-013 | Parent wait/settle behavior MUST be bounded, acyclic and truthful about failures/cancelled/unknown descendants; required unresolved work MUST prevent root success. | AT-DLG-013 |
| OM-DLG-014 | P6 release qualification MUST separately identify local workers, remote workers and relocation, with exact artifacts and independent race/failure evidence for every advertised profile. | AT-DLG-014 |

## Attenuated authority and admission

The frozen child request binds task/root UUID, parent native process ID, original native submission ID, template digest, canonical input digest, selected worker host/installation, authority/store/runtime identities, caller and child capability lineage, resource inventory, policy/contracts, budget allocation and expiry. The native process host resolves the authenticated caller and installed template. Guest-supplied fields never select an issuer, signer, executable, transport destination or confidentiality policy.

Native authority validates the complete chain at admission and again at dispatch where its contract requires it. Child scope is a subset of the parent's permitted resources/actions, including path/destination/argument constraints. Child expiry cannot exceed parent expiry. A child cannot appoint itself as another parent, switch tenant/account, escape revocation through a new profile or trade an expired parent capability for fresh authority.

Child signing keys stay in native custody. The candidate process store contains persisted signer material and therefore belongs to the trusted native state boundary. The guest has neither file access nor a serialization API for it. Desktop same-UID file modes are not protection against a malicious trusted desktop plugin; a stronger host threat model needs a separate privileged isolation design.

Admission and launching are two distinct events. After durable child admission commits, a launcher may start the exact template only if its native launch claim remains valid. A crash after admission but before launch recovers the same child. A crash after possible launch requires ownership reconciliation. The controller may repeat the same idempotent request; it must not allocate a new native submission because the response was lost.

The initial proposed local policy defaults are eight total processes including the root, maximum depth two edges, at most two active child workers, 64 tree logical calls and child TTL no longer than 15 minutes or the parent's remaining validity, whichever is shorter. Child input is bounded to 64 KiB canonical JSON, matching the inspected native submission bound. Limits are defaults for qualification, not performance claims or promises that the native runtime already enforces the whole proposed policy.

The process runtime's tree logical-call counter is distinct from resource invocation budgets and monetary policy. Denied and uncertain admitted logical calls consume their slot; replay of the same logical call does not consume another. Sibling basis-point shares must fit the parent, including intermediates that only spawn grandchildren. Cancelled children retain their reserved shares in the inspected runtime; automatic reclamation is not implemented. The proposed profile does not grant refunds based on missing responses or observed idle time.

Model accounting must also aggregate across children. The current Pi `openRunBudget` provides a retained per-profile budget; separate children cannot each receive a fresh copy of the full parent ceiling. Until a qualified tree reservation service or conservatively preallocated non-overlapping child ceilings exists, multiworker model execution remains unavailable. Codex subscription children retain `null` hard output-token budget fields; a parent requiring hard token or money guarantees must refuse that provider profile rather than fabricate a bound.

## Ownership, leases and cross-host communication

Local writer ownership uses native store/gateway custody, never just the desktop task lock. For remote workers, the proposed worker lease binds authority/store/runtime, child process, exact admitted launch, destination host identity, owner generation, policy/install digests and deadline. Issuance, renewal, loss and replacement must be native-authority operations. A display heartbeat does not renew a lease or prove that the old worker stopped.

Initial proposed remote defaults are a 30-second admission lease, renewal at most every 10 seconds and maximum accepted clock uncertainty of 2 seconds, all bounded by parent expiry. Qualification must demonstrate the selected authority's clock/fencing contract; unsupported clock guarantees keep remote mode unavailable. Lease validity is checked at admission by the authority's clock. Old generations cannot admit work after replacement. An unreachable worker stops starting new work when its valid lease cannot be established; it does not continue offline under cached permission.

Lease expiry does not cancel a packet already accepted by an external provider or prove OS death. If the old worker may still be executing, the authority must preserve that original operation and fence overlapping work. Reassignment requires either positive stopped/undispatched evidence or the selected native recovery protocol. A network partition is uncertainty, not evidence that the remote machine disappeared.

A remote worker may reach only the selected authenticated worker endpoint and admitted relay/resource routes. The proposed transport must pin host identity and native authority, protect credentials in transit and carry replay-resistant request/response bindings. It does not expose SSH agent, Docker/container-engine, compositor, session bus or operator control sockets to the guest. Transport connection success is not a capability grant. Broad remote command execution remains a trusted deployment activity outside model-callable tools.

Remote context release requires the same selected disclosure mode as the host contract. Bind content/artifact digests, recipient worker/host, provider/account when applicable, and current scope/expiry. Do not export arbitrary parent transcripts or copy provider credentials into a child. `execution-only` disclosure stays explicitly scoped and visible. Label-aware native custody or required model release remains unavailable until its native facade is independently delivered.

## Durable identity, handoff and recovery

There are three identities to retain: the desktop task tree identity, the native child/admission identity, and each native operation's immutable request identity. A worker host ID, boot ID or lease generation may change only through a native-supported transition; the original operation identity does not change merely because delivery moved.

The proposed original-operation custody record includes the authority/store/runtime identity, original process/parent lineage, original logical key and native request/operation IDs, canonical argument/request digests, resource owner, selected route/participant contract, admission/dispatch state, trusted signer, receipt/result digests, delivery state, owner generation, expiry and continuation references. Secrets and delivery proofs remain in private owner custody. A UI projection carries opaque references and safe summaries.

No new desktop operation ledger duplicates native dispatch truth. A desktop mapping may bind task IDs to native IDs and store observation cursors, but only the native owner advances authoritative admission, completion, delivery and recovery. Queue messages, JSON status, worker checkpoints and logs are not substitutes for those records.

For optional stopped-state relocation, stop work, settle or retain all original operations, stop host services and prove no owned guests/containers survive. The native exporter seals and retires the source, preserving the authority, receipts, budgets, revocations, process/checkpoint state, runner ownership, original mappings, delivery records and required artifacts. Transfer privately, verify complete inventory and compatible ABI, then import through the native relocation operation. A receipt-only copy or a new authority database is not a resume. Missing/mutated state refuses; partial import is reconciled using the original relocation identity. Copied live socket and PID files do not establish ownership at the destination.

Candidate native relocation covers its own host-state directory. Pi private gateway mappings, model reservations, native history/ACK observer custody and resource-owner generations must be included or explicitly retained at their original authenticated owner through a compatible protocol. The existence of native export/import does not prove this whole integration transfers correctly. Live migration and simultaneous source/destination writers remain unavailable.

For optional remote workers with the authority remaining at its original host, child crashes are recovered by that same authority. Resume never resets per-child or tree budgets. A result that reached the provider but not the authority remains unknown even if the new worker can issue the same HTTP request. A provider idempotency key helps only when the selected provider contract guarantees its scope, retention, request equality and authoritative lookup; it is not a universal exactly-once contract.

The candidate native runtime has a separate side-effect-free-tool retry exception. Initial Omarchy profiles leave automatic fresh attempts disabled. Any later opt-in must prove the resource's read-only contract and preserve the original unknown attempt plus the explicitly linked new attempt. Effects with unknown outcomes never receive a fresh identity to escape the fence.

## Cancellation and parent settlement

Cancellation is monotonic for new native admissions throughout the selected subtree. Native admission cancellation, transport shutdown, model-stream abort and OS worker termination are separate observable actions. The native process cancellation transaction decides whether work was admitted before the cancel. Previously admitted effects may still finish; cancellation does not revoke capabilities used outside the runtime or undo remote effects.

Use `cancelling` while native cancellation or process cleanup is incomplete. Use `blocked_unknown` when an original effect or worker custody remains unresolved. Use `cancelled` only when the selected cancellation contract is complete and known effects are still visible. Remote disconnection is a connectivity state, not a terminal outcome.

The native dependency graph must reject cycles. `wait_children` and `settle_children` operate only on admitted descendants/dependencies selected by the current run, with bounded wait and cancellation. Parent success requires its selected required children to finish their declared work, all necessary original outcomes to be verified and delivered, required tests/artifacts to pass and no unresolved child effects. An explicitly optional child failure may be recorded in the reviewed task policy, but it never hides an unknown operation. Root cancellation cannot silently turn unknown children into successful skipped work.

## Proposed acceptance cases

Each artifact names the exact local/remote/relocation profile, native build, authority/store identity, host installations, templates, resource contracts, limits and independent observations. Synthetic transport tests remain labeled synthetic. Cross-host cases require two independently observed hosts for a release claim.

### AT-DLG-001: Native prerequisite gate

Trigger: request children with only the public Pi package, a complete callback-shaped facade, no process host, incompatible native ABI and a serving-only process host. Observable outcome: delegation refuses before child credential issuance or launch, and reports the missing artifact precisely. Independent oracle: native process table, issued-credential counter and independent OS process observer. Evidence artifact: `AT-DLG-001-prerequisite-gate.json`.

### AT-DLG-002: Attenuation and lineage rejection

Trigger: admit a permitted read-only child; then try widened path/action, changed issuer/tenant/account, extended expiry, sibling impersonation, missing/replaced delegation hop and a revoked ancestor. Observable outcome: the valid child works only within its grant; every invalid variant refuses without effect. Independent oracle: independently verified signed chain, native budget family and resource effect/canary audit. Evidence artifact: `AT-DLG-002-attenuation.json` using real kernel admission.

### AT-DLG-003: Child admission crash and duplicate race

Trigger: submit the same native child request concurrently, lose its response, crash after commit before launch, then repeat with changed template/input/share. Observable outcome: one retained child/launch identity for equal requests, conflict for changed bindings, no lost or double-issued signing custody. Independent oracle: native transaction/store inspection and separate launch counter. Evidence artifact: `AT-DLG-003-child-admission.json` with original request and launch IDs across every cutpoint.

### AT-DLG-004: Immutable launch template

Trigger: request a registered template, inject executable/argv/env/package/socket selectors into child input, alter installed binary/runtime hash and attempt guest access to parent keys or protected host sockets. Observable outcome: only the exact qualified template launches, injected selectors refuse, and guest probes fail. Independent oracle: measured executable/mount/namespace inventory, credential canaries and host listeners. Evidence artifact: `AT-DLG-004-template-confinement.json` on the advertised x64 profile.

### AT-DLG-005: Tree and provider aggregate ceilings

Trigger: concurrently cross depth/process/concurrency/logical-call/sibling-share ceilings, cancel a child and attempt to reclaim its share, then restart children after the last model reservation. Observable outcome: admitted totals never exceed frozen ceilings, cancelled shares are retained, original replay does not double-charge a logical slot and restart cannot mint a new model allowance. Independent oracle: native transactional budget tables, provider request captures and process observer. Evidence artifact: `AT-DLG-005-tree-budgets.json`, including unavailable hard-token fields for subscription workers.

### AT-DLG-006: Expiry and cancellation admission races

Trigger: race parent expiry, ancestor revocation and subtree cancellation against child admission and an already-admitted held resource call; disconnect one remote worker during cancel. Observable outcome: admissions after the native boundary refuse, admitted effects remain truthfully recorded, surviving/unknown children remain visible and no result implies rollback. Independent oracle: native transaction order, independent effect counter and OS/process lease observations. Evidence artifact: `AT-DLG-006-cancel-expiry.json` with separate admission, effect, delivery and termination states.

### AT-DLG-007: Original operation survives worker replacement

Trigger: kill a worker before dispatch, after effect before outcome retention and after outcome retention before delivery; resume on the selected same or second host with identical and changed logical inputs. Observable outcome: native original identities and immutable digests persist; changed inputs conflict; completed originals replay their exact receipt/result; uncertain effects do not redispatch. Independent oracle: original signed records and independent resource effect count. Evidence artifact: `AT-DLG-007-original-identity.json`.

### AT-DLG-008: Fenced ownership under partition

Trigger: hold a worker across lease expiry, partition renewal, inject greater-than-2-second clock uncertainty, reuse a PID after reboot and start a competing owner generation. Observable outcome: stale/uncertain owners cannot admit new work, one owner generation holds custody, and timeout/PID alone never authorizes a duplicate launch or effect. Independent oracle: authority-clock admission records and process observation on both hosts, with a paused in-flight effect retained as uncertain. Evidence artifact: `AT-DLG-008-owner-lease.json`; unsupported native lease semantics leave remote mode disabled.

### AT-DLG-009: Remote authentication and disclosure

Trigger: connect a wrong host/worker/authority, replay a request under another lease, alter recipient/artifact digest, attempt a raw host-control socket and request prohibited parent transcript context. Observable outcome: all invalid paths refuse before disclosed bytes or resource effects; an exact allowed child receives only its admitted content. Independent oracle: destination-side capture, resource audit and secret-canary checks outside the worker. Evidence artifact: `AT-DLG-009-remote-boundary.json` without raw confidential payloads in the report.

### AT-DLG-010: Stopped-state handoff and interrupted import

Trigger: export with a live worker, missing original record or unresolved container owner; separately export a stopped complete state, corrupt one file, interrupt native import and attempt source/destination concurrent serving. Observable outcome: incomplete/live/corrupt state refuses; valid import retains authority and original operation IDs, counters and delivery state; source cannot resume serving; interrupted import reconciles the same relocation. Independent oracle: native relocation seals, complete content manifest, private Pi/resource state crosswalk and simultaneous process/resource observers. Evidence artifact: `AT-DLG-010-custody-transfer.json`.

### AT-DLG-011: Unknown remote effect stays unknown

Trigger: an independently observed external effect loses its response and provider lookup is unavailable; later provide a forged result, mismatched idempotency key and finally valid owner-bound original evidence. Observable outcome: the task remains `blocked_unknown` until valid reconciliation; no attempt acquires a new identity to repeat the effect; exact completed evidence permits only original delivery. Independent oracle: provider-owned effect log/lookup and kernel original records. Evidence artifact: `AT-DLG-011-remote-uncertainty.json`; the report states the selected resource guarantee instead of general exactly-once behavior.

### AT-DLG-012: Child output verification before ingestion

Trigger: child reports success with forged receipt, changed result, foreign signer, missing disclosure grant and a valid native completion; pause ACK while detaching/replacing its host observer. Observable outcome: unverified/prohibited bytes do not enter parent context or receive ACK, valid bytes follow exact native delivery, and writer custody stays held through pending ACK. Independent oracle: parent native history/context digest, owner delivery latch and independent signature verifier. Evidence artifact: `AT-DLG-012-child-delivery.json`.

### AT-DLG-013: Bounded dependency settlement

Trigger: request a dependency cycle, wait on a sibling outside the admitted dependency set, hang a required child, fail a test and leave one optional child with an unknown effect. Observable outcome: invalid waits refuse, bounded waits expose timeout/cancel actions, required failed checks prevent success and every unknown effect prevents clean root success. Independent oracle: native dependency graph, independently verified child artifacts and task projections checked against original native states. Evidence artifact: `AT-DLG-013-parent-settlement.json`.

### AT-DLG-014: Qualification cannot spread between profiles

Trigger: pass local-worker tests, then select an unqualified remote host, changed architecture/template, live migration or a new provider. Observable outcome: only the named exact qualified local profile enables; other capabilities remain visibly unavailable until their complete applicable matrix passes. Independent oracle: public installable artifact provenance, profile manifests and independent clean-install report. Evidence artifact: `AT-DLG-014-profile-release.json` with every open and skipped gate recorded explicitly.

## Risks and prerequisite owners

The process-runtime maintainer owns immutable lineage, durable admission, budget-family accounting, native cancellation and original-operation semantics. The process-host maintainer owns fixed templates, confined launch, worker ownership and supported relocation. The Pi maintainer owns native facade integration, per-child host restriction, model-budget allocation and exact result/ACK custody. The provider/resource maintainer owns the actual effect and its reconciliation guarantees. The independent verifier owns two-host fault injection and clean-install evidence.

Before local P6 activation, deliver `native-delegation-profile.json` and its exact native compatibility/confinement prerequisites from [readiness](research/chio-readiness.md). Before optional multihost activation, additionally deliver `cross-host-custody-profile.json`, native remote lease/fencing behavior and the complete Pi/resource state transfer crosswalk. A UI tree, successful child subprocess or signed advisory recovery suggestion closes none of these gates.

Public anchors: [Pi child facade](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/delegation.ts), [native port contracts](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/governance.ts), [native prerequisites](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/NATIVE-PREREQUISITES.md), [core signed attenuation types](https://github.com/backbay-labs/chio/blob/5b8bec41d32f3838b880576fe6123c983ecebf8d/crates/core/chio-core-types/src/capability/attenuation.rs). Candidate-only API locations and exact inspected file fingerprints are in the readiness source map; no public checkout command assumes they exist in public main.
