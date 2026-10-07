# Durable state, stop, restoration and evidence

Status: proposed normative design. Confidence: high in state ownership and recovery rules; unknown in installed durability/rollback behavior. This depends on [kernel contracts](03-kernel-contracts.md) and [native authority](04-authority-integrity.md). Current stores and missing native contracts are pinned in [readiness](research/chio-readiness.md). A recovered interface is not evidence that authority or an external effect recovered.

## State owners and truthful projections

| State | Owner | Restart rule |
| --- | --- | --- |
| Operation identity, intent, reservations, dispatch and native terminal | Native admission owner | Reconcile original operation under current serving fence; no new identity to hide uncertainty |
| Approval, influence, stop chain, closure, capability and budget | Native authority and same-writer participants | Validate durable heads/generations and pending restrictions before mutation readiness |
| Raw return and release decision | Native tool-outcome/knowledge owner | Retain bytes before post-return evaluation; never redeliver by UI cache alone |
| Task labels, selected tab, display order, transport retry records | Shared desktop controller | Rebuild display from native authority; corruption may lose presentation, never relax authority |
| VM/native worker lifetime | Host supervisor plus observed incarnation | Query live process/VM identity; stale handle or missing observation is unknown |
| ES/NE restriction and coverage | Native provider instance | Re-authenticate and synchronize current restrictions; stale view can deny but cannot resume |
| Remote provider/resource effect | External participant with qualified lookup/evidence | Verify finality for exact request/account/destination; disconnect is not non-execution |
| Sensor events | Named sensor source | Gaps, restarts and dropped ranges remain explicit; cannot synthesize past observations |

The task projection is a product view over these facts. Suggested display states are `preparing`, `running`, `review_required`, `stopping`, `stopped`, `completed`, `blocked_unknown` and `unavailable`, but exact shared wire enums belong in [06](06-operator-protocol.md). Each state is accompanied by independent native facts. `stopped` requires native admissions fenced and the selected profile's worker/restriction closure evidence. A completed task requires all applicable outcomes and releases accounted for. If worker absence is known but a publication is unresolved, display stopped execution with unresolved external outcome; never collapse it into success or harmless cancellation.

## Native stop procedure and race disposition

1. Authenticate the native stopping principal and exact authority scope. Record restrictive process latch immediately when available. A process latch is useful but not durable.
2. Native owner persists stop intent in the independent stop-intent journal, then commits the signed stop-chain transition and required anchor. Acknowledgement distinguishes `process_only`, `latch_only` and `durable` native evidence. No desktop database write upgrades those classes.
3. Serving writer denies new dispatch/authorizing crossings after the stopped head and withholds later output/artifact/confined releases according to each crossing's declared ordering point. Settlement of already committed subjects remains possible under subject-before-cut proof.
4. Controller requests supervisor termination and provider restrictions, recording requested, observed and failed facts separately. Guest stop request and confirmed forced termination are different observations. A killed worker does not close a dispatched host broker or remote call.
5. Reconciliation identifies each original committed operation and obtains qualified finality or retains unknown. Already delivered bytes/effects are not recalled. Resume is a new authenticated native decision against the current head, never a reconnect side effect.

Stop identity includes authority, scope, chain generation and epoch. Resume/relax compare the whole current head. A pending intent cannot be retired just because a higher epoch exists: its exact intent ID and generation must be satisfied in the anchored ancestry, with equal or narrower containment and no subsequent widening. An unreadable journal blocks widening. Stops from different scopes cannot overwrite one another. A failed journal write reports only process restriction; an offline helper that exits cannot claim a surviving process latch.

| Scheduling cut | Allowed outcome | Forbidden conclusion |
| --- | --- | --- |
| Stop ordered before dispatch intent | Dispatch refuses | Cached pre-stop permit authorizes a new effect |
| Intent ordered before stop, effect not yet observed | Committed effect may still occur | Stop means no effect can occur after click time |
| Return recorded, output release ordered after stop | Bytes retained and withheld | Worker returned means client received output |
| Release committed before stop, sink IO pending | Apply exact crossing's release contract; delivery may finish | A later stop retroactively rewrites release order |
| Confined-return admission before stop | NK-02 ordering applies; final process-activity/latch check still applies | Final activity read is a second durable stop crossing |
| Native stop reply lost | Reconcile stable original stop intent | New request silently replaces incident or claims success |
| Store/anchor commit uncertain | Owner poisoned, mutations unavailable, original state reconciled | Optimistic success, compensation or fresh dispatch |

## Crash and restart matrix

| Crash cut | Required native startup action | Independent oracle |
| --- | --- | --- |
| Before original operation begin | Reconcile stable client intent; create only if native owner proves no original | Exactly one native operation at most |
| Prepared/reservations acquired before dispatch commit | Pure machine compensates only proven pre-dispatch participants | No host effect; each reversible reservation released once |
| Dispatch committed before resource call/reply | Query original resource status where qualified; otherwise unknown | No automatic redispatch of side effect; retained charge/commitment |
| Resource accepted, return record absent | Preserve unknown until exact provider/resource evidence resolves | External request counter and original ID agree |
| Return recorded before post-return result | Resume post-return obligations against retained exact bytes | No resource reinvocation; release policy/current stop rechecked |
| Terminal projection before receipt-store append | Repair secondary receipt projection from canonical native terminal | Same receipt bytes/signature and no duplicate effect |
| Native approval consumed before response | Read original consume/result | One consume despite controller restart |
| Stop intent durable before signed stop | Honor pending restriction and apply/reconcile it under writer | No mutation readiness before restriction is recovered |
| Signed stop anchored before intent retirement | Verify exact satisfaction and retire only that intent | No stale pending stop resurrected after a valid later resume |
| Event-end acknowledgement races transport rebase | Serialize on stable subscription owner; discard stale publish candidate | End marker cannot be resurrected or removed from another subscription |

Sleep/wake is a revalidation boundary. Authority time and expiry come from the native time contract; local monotonic clock values do not compare across boot. Expired grants, stale extension generation, VM disconnect and provider loss move affected profiles to unavailable or restricted pending reconciliation. No wake handler replays approvals, advances stop to running, or creates an untracked worker.

## Restore and update policy

The default restoration feature restores presentation and evidence for inspection. Resuming authority after an arbitrary Time Machine, APFS, whole-volume or VM snapshot restore is unavailable unless the selected deployment has an independently qualified non-rollbackable freshness source and a native restore protocol. Merely copying the database and an adjacent anchor is insufficient. A signed fresh witness must bind the authority/store identity and exact head digest, not just a higher numeric epoch.

Native restore first checks local anchored ancestry against that external floor, store/schema compatibility, spent approvals/nonces, stop intents, reservations, revocations and influence history. An ancestry fork at the same or later position refuses readiness. Once accepted, native ownership rotates the restore/launch generation and rebinds credentials/operation namespaces according to the delivered native protocol. The procedure never relabels unresolved original operations as new work. A guest snapshot is data under a fresh launch, not a reusable capability bundle; inherited descriptors, channels, secrets and nonces must be invalidated before any effect.

Without a freshness source, the only supported recovery is read-only inspection and an explicitly new authority deployment that cannot replay previous operation authority. Old external effects remain unresolved or historically verified; new deployment does not settle them. This is an availability restriction, not a promise to detect an undetectable full-host rollback using local files.

Upgrade tests cover the exact app/controller/kernel/store/extension contract tuple. A migrated authority store refuses an incompatible older writer. UI rollback may read compatible historical projections but cannot roll back authority schema, stop generation, signing roster or policy. Atomic activation and distribution are in [12](12-distribution.md).

## Evidence and storage

Native evidence retains canonical signed receipts, original operation references, stop/closure facts, trust roots and checkpoint proofs. Controller evidence adds profile/installed tuple, worker incarnation, resource observation, ES/NE coverage and explicit gap ranges. Original signed bytes stay intact; redacted projections are distinct artifacts with their own digest and redaction statement. A signed native decision proves what that authority recorded; a sensor proves what it observed; a remote provider report keeps its declared assurance class.

An export manifest binds artifact digests, source/runtime identity, selected profile, retention omissions and independent verifier results. Tenant/user boundaries derive from native read authority; an omitted tenant does not imply admin. Current `EvidenceExportBundle` is a reusable receipt envelope, not automatically the complete Mac package. Missing checkpoint coverage uses its explicit uncheckpointed status. A hash chain without independent witnessing cannot claim public non-equivocation. A shape validator never replaces signature, receipt, ancestry or resource-finality verification.

Controller queues and evidence retention are bounded. At configured capacity, new task/effect admission closes before consuming the reserved recovery capacity. Critical stop/recovery facts cannot be evicted to preserve cosmetic UI history. On real ENOSPC or denied fsync, report actual native stop durability and invoke available restrictive teardown; do not assert durable cancellation. Resource capacity and privacy retention limits are set and measured in [13](13-privacy-performance.md).

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| MAC-REC-001 | Task state MUST derive from native operation facts and independent host observations; completion, admission stop, worker exit, release and external finality MUST remain distinct. | AT-MAC-REC-001 |
| MAC-REC-002 | Controller restart and mutating retry MUST reconcile stable original intent and native operation before any creation or dispatch. | AT-MAC-REC-002 |
| MAC-REC-003 | Crash recovery MUST use the native pure admission classifier and exact persisted participant evidence; unknown effects MUST retain commitments and forbid blind redispatch. | AT-MAC-REC-003 |
| MAC-REC-004 | Stop MUST report actual process-only, journal-only or anchored durability and MUST recover pending native restrictions before readiness. | AT-MAC-REC-004 |
| MAC-REC-005 | Stop intent retirement and resume MUST verify exact incident, generation, ancestry and current head; pending or unreadable intent MUST block widening. | AT-MAC-REC-005 |
| MAC-REC-006 | Stop races MUST preserve per-crossing order and subject-before-cut settlement; host teardown MUST NOT substitute for native outcome closure. | AT-MAC-REC-006 |
| MAC-REC-007 | Sleep, wake, reboot and user-session changes MUST revalidate native time, authority, platform identity and restrictive convergence before affected mutations resume. | AT-MAC-REC-007 |
| MAC-REC-008 | Authority restoration MUST require a qualified freshness source outside the restored snapshot domain; unsupported whole-host restore MUST remain inspection-only. | AT-MAC-REC-008 |
| MAC-REC-009 | Accepted restore MUST advance native restore/launch generation and invalidate stale capabilities, approvals, nonces, child handles and guest channels without losing original unknown effects. | AT-MAC-REC-009 |
| MAC-REC-010 | Store migration and component upgrade MUST be atomic or recoverable and MUST refuse older/incompatible writers rather than reinterpret newer authority. | AT-MAC-REC-010 |
| MAC-REC-011 | Retained canonical terminal/return evidence MUST repair secondary projections idempotently without reinvoking a resource or silently changing signed bytes. | AT-MAC-REC-011 |
| MAC-REC-012 | Event end acknowledgement MUST bind stable subscription identity and authenticated owner; dropped/rebased sensor or transport events MUST preserve honest gaps. | AT-MAC-REC-012 |
| MAC-REC-013 | Evidence export MUST bind exact profile/runtime, native facts, host observations, retention gaps and trust roots while preserving source assurance classes. | AT-MAC-REC-013 |
| MAC-REC-014 | Independent verification MUST validate signatures, inclusion/ancestry and effect-specific evidence; shape-only or same-operator records MUST NOT claim independent qualification or public witnessing. | AT-MAC-REC-014 |
| MAC-REC-015 | Retention and export MUST enforce native user/tenant read authority, keep signed originals distinct from redactions, and never store or export signer/credential secrets. | AT-MAC-REC-015 |
| MAC-REC-016 | Storage exhaustion and queue saturation MUST close new work, preserve bounded recovery routes where feasible, and report failed durability honestly. | AT-MAC-REC-016 |

## Acceptance procedures

| Acceptance | Setup/action | Expected independent evidence |
| --- | --- | --- |
| AT-MAC-REC-001 | Construct all combinations of worker absent/present, admission stopped/running, external known/unknown and output released/withheld. | Projection truth table never shows complete harmless stop when a dimension is unknown; underlying facts remain inspectable. |
| AT-MAC-REC-002 | Kill controller after native commit before reply; restart twice and resend identical intent; mutate intent payload once. | Same operation/receipt or explicit conflict; independent effect count remains one; transport ID changes do not change native identity. |
| AT-MAC-REC-003 | Fault each crash-matrix cut and reconcile with/without authenticated resource finality. | Native machine trace matches retained state; pre-dispatch compensation only when proven; unknown stays retained and no effect redispatch occurs. |
| AT-MAC-REC-004 | Fail intent write, fail database commit, fail anchor sync, then restart; repeat offline helper stop. | Accurate durability class at each cut; pending journal blocks admission after restart; offline exiting helper never reports process-only as a durable stop. |
| AT-MAC-REC-005 | Pending stops for two scopes; narrow one, inject stale resume and higher unrelated epoch; crash before intent retirement. | Neither scope disappears; stale resume refuses; exact satisfaction retires only matched generation; no stale candidate widens or re-stops valid resumed state. |
| AT-MAC-REC-006 | Barrier-schedule intent/stop/release and kill worker during host call. | Writer order explains allowed effect; post-stop release withholds under declared disposition; resource finality remains independent of observed exit. |
| AT-MAC-REC-007 | Sleep past expiry, restart provider, switch user, reboot with stopped head and pending original effect. | No automatic resume; native time/generation rejection; other user sees no state; only qualified original reconciliation changes outcome. |
| AT-MAC-REC-008 | Restore database only, database plus local anchor, full guest snapshot, and forked chain at same numeric head. | First rejects/recovers only proven extension; whole snapshot requires independent exact digest floor; unavailable witness denies mutation; fork fails ancestry verification. |
| AT-MAC-REC-009 | On qualified restore, replay old approval, spent nonce, launch handle, child signer handle and unacknowledged original effect. | Stale generations refuse; original operation remains queryable/unknown; new launch has fresh authority binding and no old channel capability. |
| AT-MAC-REC-010 | Interrupt migration at each transaction boundary and activate old kernel/new store or new helper/old protocol. | Compatible restart completes safely or refuses; no partial migrated-ready state; no drop of stop/influence tables to regain availability. |
| AT-MAC-REC-011 | Delete secondary receipt projection after native terminal; duplicate return projection; restart and export twice. | Canonical native receipt bytes/digest identical; one logical receipt/effect; no fresh resource call; missing originals produce explicit evidence failure. |
| AT-MAC-REC-012 | Rebase transport between end creation and ACK; deliver stale ACK from different session; drop sensor sequence range. | Owner serializes stable ID; no marker resurrection or cross-session acknowledgement; sensor gap retained and crossing order untouched. |
| AT-MAC-REC-013 | Export exact successful run then remove worker evidence, replace architecture, omit unresolved operation or checkpoint coverage. | Bundle is incomplete/mismatched/uncheckpointed as appropriate; no derived success; all artifact digests and original references independently check. |
| AT-MAC-REC-014 | Tamper receipt, inclusion proof, witness trust root and external finality binding; supply schema-valid unsigned fixture. | Native/offline verifier rejects each relevant tamper; fixture remains component evidence; independently operated witness claim requires its actual signed/checkable record. |
| AT-MAC-REC-015 | Export user A as user B, omit tenant, redact a signed payload in place, and scan outputs for injected secret canary. | Read-boundary rejection; original signature unaffected by separate redaction; no canary or unauthorized rows; omission explained without revealing protected content. |
| AT-MAC-REC-016 | Fill normal quota, saturate event queue, force real ENOSPC and fail recovery fsync. | New admission stops; existing recovery capacity tested separately; actual durability class retained; no dropped critical event is described as complete evidence. |

## Dispositions and dependencies

Native receipt-store repair and recovery-claim fencing exist and are reusable. Full Mac task recovery, NK-04 durable stop, NK-05 restored influence, external freshness verification and generation-safe guest/process restore remain prerequisites. Generic live migration and transparent suspended-process restoration are not selected for the first release. [M6](../../plans/2026-10-07-macos-integration/06-recovery-evidence.md) supplies acceptance before VM execution M3, publication M4, native enforcement M5 and delegation M7 can claim their respective closure. Distribution M8 qualifies the resulting exact profile.
