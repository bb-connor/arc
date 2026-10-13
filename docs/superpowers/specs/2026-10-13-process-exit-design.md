# Process exit as an authority transition

Status: Proposed

Scope: terminal process authority, authenticated host reporting, and its composition with [authority-space closure](2026-10-04-authority-space-teardown-design.md). The [kernel roadmap](../../operations/UNIFIED_ROADMAP.md#lane-kernel-the-guarantees-outside-teams-rely-on) requires an exited process to refuse invocation and a closed subtree to leave its parent and siblings usable.

## 1. Contract

An authenticated terminal report ends one process's authority before the host acknowledges completion. Exit is durable and irreversible. An exited process cannot invoke tools, prepare invocation authority, create children, change checkpoints, store new blobs, register new waits, or receive fresh worker credentials. Authorized historical reads remain available.

Exit belongs to the process authority. Runner status, worker credential deletion, an OS exit code, or absence of a worker does not independently establish it. Tool-call receipts retain their own original operation identities and settlement obligations. A process exit record never replaces a tool receipt, proves remote effect absence, refunds a hold, or erases knowledge.

The proposed default preserves live children under their own capabilities. Parent exit ends the parent's own invocation and mutation rights. Explicit subtree cancellation closes the selected process and its descendants. Neither action releases process shares or logical-call consumption.

## 2. Process and attempt states

The process state is `Running`, `Cancelled`, or `Exited { outcome_digest }`. A durable exit intent blocks new authority while its terminal commit is incomplete. It does not create another runnable state. There is no transition from a terminal state to `Running`.

The host classifies the exact worker attempt using its retained plan, attempt counters, authenticated native observations, and existing supervision policy:

| Observation | Process disposition |
| --- | --- |
| Observed success | Commit terminal exit with a successful outcome. |
| Observed failure with an authorized retry remaining | Keep `Running`; retain the failed attempt and its spent retry allowance. |
| Failure that exhausts retries, or an explicitly terminal failure | Commit terminal exit with the failed outcome. |
| Exit code 75 with an accepted retained wait and remaining suspension allowance | Keep `Running`; retain the suspension and its accounting. |
| Exit code 75 without that wait | Apply the ordinary failed-attempt policy. |
| Suspension allowance exhausted | Commit terminal exit with the exhausted-allowance outcome. |
| Launch or wait whose disposition remains uncertain | Refuse replacement of the unresolved native attempt. If the runner policy ends the process, commit an outcome-unknown exit retaining the native ownership and effect uncertainty. |
| Explicit cancellation wins | Preserve `Cancelled`; exit reporting cannot replace cancellation with success. |

A diagnostic, log, cleanup, or status-publication failure after observed success cannot change the child's outcome to failure or authorize another attempt. The runner's command exit status is not the child's authority outcome. An outcome-unknown record states that authority has ended; it makes no claim that an unobserved OS process or remote effect has stopped.

## 3. Authenticated terminal reporting

Only the trusted host that owns the process runtime reports exit. A worker bearer credential does not authorize this operation, and the worker protocol adds no caller-selected exit or process selector. Direct embedding callers use the same authenticated host path; a raw process id and caller-supplied outcome are insufficient.

Before launch, the process authority retains the process/runtime namespace, capability digest, plan binding, monotonically identified attempt, and current host ownership binding. A report must match this retained attempt and the native observation selected by the host. The host validates private directory identity and its exclusive ownership; an expired, replaced, or unrelated owner cannot commit a report. An ephemeral runner `run_id` is diagnostic and cannot replace the durable attempt identity.

The bounded immutable `ProcessExitIntent` contains the serving authority id, authenticated request-namespace digest, process runtime namespace, process id, capability digest, plan binding, exact attempt and reporting-authority bindings, disposition, bounded native observation or unresolved-ownership reference, tagged usage evidence/reference, original authority timestamp, and original signing identity. It contains neither its own digest nor a fence identity, fence commit reference, or final outcome digest. Successful and failed observed outcomes include the native terminal observation. An uncertain outcome names the retained unresolved ownership record. The host cannot turn missing evidence into success.

`intent_digest = SHA256("chio.process-exit-intent.v1\0" || canonical(intent))`. The deterministic process-self fence identity is `SHA256("chio.process-exit-fence.v1\0" || canonical({ serving_authority_id, request_namespace_digest, process_runtime_namespace, process_id, intent_digest }))`. This identifies the restrictive fence request; it does not predict a writer commit. The closure owner stores the exact intent binding and returns its actual durable commit reference on installation or identical replay. Conflicting material at that identity refuses.

Only after verifying that readback does the host construct the final exit body. Its `outcome_digest = SHA256("chio.process-exit.v1\0" || canonical(exit_body))` is distinct from the intent digest. Neither the outcome digest nor the signature appears inside its own body. Store, clock, signer, or observation failures refuse acknowledgement and retain the pending intent for recovery.

The signed artifact uses the initial `chio.process-exit.v1` shape. Its required body binds:

- Serving authority, authenticated request namespace, process runtime namespace, and process id.
- Capability digest and plan binding.
- Exact attempt identity and authenticated reporting authority.
- Successful, failed, or outcome-unknown disposition, with the corresponding bounded observation reference.
- Tagged observed, partially observed, or unavailable attempt usage and its retained accounting reference. Known values are preserved; unavailable values are explicit and cannot be replaced by zero.
- The process-self closure fence identity and commit reference.
- The original intent digest, authority timestamp, and signing identity, equal to the retained intent.

The body contains no credentials, environment, command output, or unbounded diagnostics. Identifiers use existing process bounds; each canonical intent and exit body is limited to 16 KiB. Unknown fields, duplicate keys, missing fields, out-of-range usage, and inconsistent disposition/evidence pairs reject before mutation. Partial usage identifies its missing fields; an unavailable marker proves no resource quantity and cannot release a charge or change retained exposure. The signature covers the final canonical exit body. The process state stores its outcome digest, and the journal retains the exact signed artifact bytes. Its timestamp is obtained from the fallible authority clock and retained with the intent; retries do not choose a new timestamp or signer.

## 4. Commit, acknowledgement, and recovery

The process journal and the durable admission writer have distinct transactions. Exit uses the shared closure mechanism to bridge them; it does not assume an atomic commit across stores.

1. Under the process writer, validate the authenticated attempt and retain the exact exit intent. The same transaction closes fresh process mutations and credential issuance. Every authority-bearing path checks for this intent in its own process transaction.
2. Derive the original deterministic fence identity from the retained intent and install its exact process-self fence through the qualified admission writer. The fence serializes with begin, dispatch capture, and output release. Installation is idempotent under the original exit identity. Failure retains the intent and refuses completion.
3. After exact fence readback, construct the final exit body using the retained intent and actual fence commit reference, and sign it with the retained identity. Commit `Exited`, its outcome digest, the exact canonical signed exit artifact, and worker credential revocation together in the process writer. A compare-and-swap verifies the original intent, attempt, state, and current qualified owner generation. Cancellation that wins this comparison remains cancellation: retain the intent's cancelled disposition, return the exact cancelled-process error, and publish no exit artifact. Recovery reaches the same result instead of leaving the intent pending. The restrictive self fence may remain. A stale signed candidate is never published.
4. Acknowledge terminal completion only after the process record and its original fence are readable. The runner completion row and status output project this committed authority result. A failure to publish diagnostics reports an operational error without undoing exit.

The exit acknowledgement does not wait for uncertain tool effects to settle. The original saga retains their receipts, holds and native ownership, and the shared drain owns their disposition. A returned process outcome is not a `Closed` artifact for that drain.

Recovery examines every unreconciled retained attempt and exit intent before credential issuance, worker launch, wait scheduling, or direct process invocation. A crash before intent persistence is not evidence that the attempt failed before execution. The prelaunch attempt binding remains the reconciliation anchor. Missing durable terminal observation keeps native custody unresolved and forbids replacement until the original native owner supplies an authenticated disposition. Memory-only reaper state, absence of an intent, and an unowned PID lookup do not authorize retry. A recovered disposition follows the retained retry policy; uncertain custody stays blocked or ends in the explicitly unknown terminal disposition, never in inferred success.

A successor host may finish a fully validated retained intent only after acquiring exclusive process-host ownership and the qualified serving owner's monotonic generation, then fencing the stale owner. The process-writer completion CAS expects that current generation while retaining the intent's original reporting authority, signer, timestamp, native references and outcome unchanged. The stale owner cannot issue new credentials, replace the attempt, or commit another result. Takeover is restrictive completion, not permission to invent an observation or reclassify a recorded terminal outcome. It resumes the original intent and fence, never creates a replacement attempt. A crash after fence installation keeps fresh dispatch denied. A crash after terminal commit returns the stored signed bytes; it does not sign again. Missing or corrupt committed artifacts and a missing referenced fence refuse readiness for that process. An unavailable original signing identity cannot be replaced with a rotated signer.

Repeated reporting with the same authenticated process, attempt, and canonical intent material returns the exact stored artifact. The comparison uses retained intent bytes; it never regenerates a timestamp or asks the reporter to supply a fence commit reference. A different body, attempt, capability, namespace, or plan for the same terminal identity returns `ProcessError::Conflict` without changing the record. Neither a repeated report nor ordinary reopen refreshes the timestamp, signature, counters, or closure generation.

## 5. Dispatch, release, and child independence

Process identity is the pair `(process_runtime_namespace, process_id)` within the authenticated serving authority and request namespace. Process ids alone are local to a journal and cannot key a shared fence. The process journal generates its persistent runtime UUID and binds it to the durable authority and kernel key (`chio-process/src/store.rs`, `Store::open`). The request-namespace digest identifies the authenticated authority and tenant; it is not a per-request identifier. The trusted host derives the process pair and its root-first ancestor pairs from this authenticated registry, then binds them into the immutable admission identity. No public input selects a runtime namespace. Caller-supplied attribution cannot select or omit these bindings.

A process-self exit fence joins only the admission's exact invoking pair. Subtree fences join the namespaced ancestor pairs, including the invoking process. An ancestor's self fence never matches a descendant's subtree-membership row. Neither join uses the tree-root capability lineage. The shared closure owner gains the exact-process selector and qualified subtree keys in its initial v1 contract; no second closure store is introduced.

`ProcessRegistry::open` requires `DurableAdmissionMode::All` and a qualified durable admission store; `ProcessRuntime::open` uses this registry for every call, including reads. Exit preserves this prerequisite. A fence committed before begin or capture refuses that crossing atomically. A capture committed first stays post-dispatch and follows the original saga. If exit wins before output release, the release is withheld under the shared closure contract. No release or settlement is inferred from process completion. Dispatch-time liveness revalidation supplements these transactional checks; it cannot replace the qualified writer fence.

The liveness rule separates three facts:

- The invoking process is `Running` and has no pending exit or matching closure.
- A cancelled or subtree-closed ancestor denies descendants.
- An exited ancestor remains an immutable delegation ancestor and does not by itself deny a running child.

All capability signatures, attenuation, expiry, revocation and family budgets remain enforced along the complete capability chain. Child survival does not skip an ancestor, issue a replacement capability, reparent the child, or reset accounting. Revoking an ancestor capability still denies descendants.

A parent can observe or join an already exited child's retained outcome under existing read and join authority. That historical child observation does not require the child to be runnable. The parent itself must retain authority to register a new wait. Completion and cleanup observers may consume retained terminal evidence after the process exits; they acquire no invocation or mutation rights.

Exit and cancellation serialize in the process writer. A winning cancellation records `Cancelled`; a later exit report cannot overwrite it. If exit wins first, an explicit subtree cancellation rooted at that exited process still closes its live descendants and installs the subtree fence. It preserves the parent's signed exit record. Cancellation remains available to an authorized operator or ancestor even when the selected root is terminal.

The runner stops only the selected cancelled subtree when applying a subtree closure. It does not abort unrelated parent or sibling workers merely because a planned worker is non-running. A subtree-closure observation is not rewritten as a terminal worker failure to trigger run-wide failure policy. A separate run-wide stop or an independently observed failure retains its explicitly declared scope. Successful `Exited` workers count as completed in run reporting; a generic `state != Running` test cannot classify them as cancelled.

## 6. Refusal surface

| Boundary | Exact contract |
| --- | --- |
| Direct invoke, preparation, spawn from an exited parent, checkpoint/blob mutation, wait registration, or credential issuance | `ProcessError::Exited { process_id, outcome_digest }`; no new call slot, child, credential, nonce, approval, output, or budget mutation. |
| The same operation while a durable exit intent is pending | `ProcessError::ExitPending { process_id }`; no mutation. |
| Invalid or stale reporting authority | `ProcessError::Unauthenticated`; no intent, nonce or terminal record. |
| Repeated terminal identity with different canonical material | `ProcessError::Conflict`; original record remains byte-identical. |
| A cancelled process | Preserve the exact `ProcessError::Cancelled(process_id)` refusal. |
| Worker request after credential revocation | Existing `unauthenticated` worker error; no attempt to reveal terminal evidence through an invalid credential. |
| Authenticated request admitted before exit whose process transaction observes terminal state | `exited` or `exit_pending` worker error, respectively, unless the final credential check produces `unauthenticated`. Tool effects and output release still obey their original admission outcome. |
| Missing committed exit evidence or referenced fence | `ProcessError::Invalid("incomplete process exit evidence")`; no process readiness, new credential or replacement launch. |

Historical inspection requires its own existing authorization. An exited process's raw capability or old credential cannot use inspection as a route to restart. Each storage/clock failure retains its concrete typed cause and denies; tests assert that cause rather than only `is_err()`.

## 7. Persistence and composition

The process journal has one v1 schema with required exit-intent and terminal-record shapes. A stale stamp is refused with the store's exact `StaleSchema` error; incomplete same-version rows fail integrity validation. Development databases with superseded layouts are recreated. No schema ladder, importer, alternate writer, alias or fallback is part of this design. Every caller, reader, fixture and supported SDK changes with the initial contract.

Durable stop blocks new work but permits authenticated restrictive exit completion and recovery. Exit uses the same authority clock and admission serving-writer fences. It does not resume a stopped kernel. Canonical terminal tool receipts remain owned by the original tool saga.

Recovery workflow and confined-child owners retain their native cancellation and terminal custody. An unqueryable native owner is recorded as uncertain and cannot be erased by an exit report. The process authority uses their qualified interfaces once present; it supplies no substitute implementation. WORK graph and delegation closure remain separate issuer-owned contracts. Production lineage enumeration is not a prerequisite for exact process-id fencing.

## 8. Acceptance

All cases assert exact errors, stable counters and record bytes, and actual invocation counts where applicable.

1. Opening a process runtime with a mode other than All returns `ProcessError::Configuration("durable admission mode must be all")`. An All-mode kernel without the qualified store returns `ProcessError::Configuration("a qualified durable admission store is required")`. Both refuse before process or attempt creation; a qualified All-mode runtime is the positive control.
2. Commit observed success and terminal failure through the trusted host. Direct invocation, preparation, child creation, checkpoint/blob writes, wait registration and credential issuance refuse with the exact exited process id and digest. Authorized inspection and outcome reads succeed.
3. Retryable failure preserves `Running` and consumes only the recorded attempt allowance. Accepted exit-75 suspension preserves `Running`; missing wait and exhausted suspension allowance follow the table in section 2. An invalid or foreign wait cannot justify suspension.
4. Replay the identical authenticated report before and after restart and reply loss. Retain identical bytes, timestamp, signature and usage. Mutate each binding and disposition/evidence pair independently; reject before mutation. A stale host or replaced attempt cannot exit a newer attempt. An authorized successor finishes the exact retained intent after owner-generation advancement, while the stale original owner refuses.
5. Crash before intent commit, after intent commit, after fence commit, after terminal commit, and before/after runner publication. Startup refuses relaunch until it reconciles the retained attempt and, if present, the exact intent. The pre-intent crash case deletes no attempt anchor and counts zero replacement launches or new credentials until an authoritative native disposition is available. Inject store, clock, signing and readback failures at each crossing. Delete or corrupt retained evidence and require exact refusal, never a successful empty projection.
6. Race exit against process mutation and credential issuance. The process writer determines one order; the loser commits nothing. Race exit against admission begin, capture and ordinary/caller/native output release. A winning fence admits no effect; a winning capture retains its original canonical terminal receipt and outstanding obligations. No duplicate effect or receipt is produced.
7. With live workers `R -> {A, B}` and `A -> A1`, exit A and prove R, B and A1 continue invoking under their original capabilities. A refuses direct host calls and fresh credentials. Preserve all sibling shares, family call counts, pins and capability ancestry across restart.
8. In the same tree, explicitly cancel A and prove A/A1 stop while R/B remain alive and successfully dispatch. Exercise the real runner, not only stored process states. Cancel the subtree after A has exited; A1 still stops and A's exit artifact remains unchanged.
9. Run two process runtimes under the same admission serving writer with equal process ids. Exit or cancel one runtime's process; only its namespaced self/subtree members refuse. Prove that a descendant does not match its exited ancestor's self fence. A forged runtime namespace refuses before any record or fence mutation.
10. Race exit against explicit cancellation in both orders. Verify terminal-state precedence, descendant behavior and exact retry results. Race child attachment against parent exit: a winning attachment survives with its original authority; a losing attachment creates nothing.
11. Join an already exited child from a live parent. Historical outcome observation succeeds without reopening the child. Revoking or expiring an ancestor capability still denies child invocation despite the exit-survival rule.
12. Preserve a reaped successful child outcome through log-drain failure, cleanup debt, status-publication failure, host interruption and restart. The CLI may report the operational failure; the child never becomes runnable or acquires a replacement outcome.

Implementation qualification covers the full library and integration suites and strict all-target Clippy of every changed crate, formatting and required security gates. Formal fence, capture and release models follow the shared closure owner. These checks do not establish hosted release qualification.

## 9. Design tradeoff

Independent child authority is the proposed default because delegation already assigns distinct capability and budget custody to each child. It preserves useful work after a supervisor completes and leaves explicit subtree cancellation as the operation that removes the whole branch. The cost is precise self-versus-subtree fencing, terminal ancestor-aware lineage validation, and explicit orphan scheduling and observation.

Cascading every parent exit into subtree cancellation has fewer state distinctions, but conflates successful completion with revocation of delegated work and can interrupt unrelated retained child obligations. Retaining only runner status avoids a process transition but leaves direct host invocation and credential reissuance unprotected. Neither alternative is the proposed contract. The child-survival rule requires review as part of this spec; it is not a claim about implemented behavior.
