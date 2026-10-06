# Design: FTL lessons program

- Status: PROPOSED (program index, revision 4: adversarial review of specs 3, 5, 8, 9 and 10 on 2026-10-05; re-baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5). Each child spec is reviewed and approved on its own.
- Date: 2026-10-04
- Scope:
  - index, cross-spec decisions and sequencing for eleven designs: seven from the FTL review, the durable stop epoch from the follow-on brainstorm, and the three keystone specs from the kernel north star;
  - the defects found while researching them, several of which need owners whether or not any child spec is approved;
  - a pointer to the follow-on brainstorm.
- Origin: review of FTL v0.1.0 (`nuta/ftl` at `b73801a`). FTL is a small Rust OS (about 23K lines, two external crates). Its kernel answers a closed set of 31 system calls and passes everything else, including Linux system calls and CPU faults, back to a per-container library OS running in user space.
- Baseline (treated as shipped):
  - `M:` = `origin/integration/process-security-m4` at `19df31ad9` (#1160): security foundation and agent processes.
  - `V:` = `origin/work/verifiable-work-session-20261003` at `14477aaac` (#1173): verifiable work (D1 dynamic delegation, S1 swarm evolution, F1 funded work), verifiers, iroh lanes, and the W1-W4 designs. W1-W4 have no code and are cited as contract anchors.
  - `R:` = `origin/research/openappa-recovery-20261001` at `de84fc306` (#1172): the recovery design docs.
  - `W:` = the **uncommitted** working tree at `standalone/arc-worktrees/recoverable-agent-runtime-20261002`. It implements recovery P0-P5, plus P6 protected setup, product reports, maintenance proposals and separately signed policy application (16 `RecoveryPermission`s, including `Maintain`). It is built on the #1160 checkpoint `f25cd61f4`. Line references reflect the working tree on 2026-10-04 and may drift. Several R: doc names (a signed `RemedyOfferV1`, the `recovery_deliveries` outbox and its cursors, an `ExplainIntent` command, emergency revocation that withdraws approvals) are not implemented in W:. The child specs use W:'s implemented names.
  - `P:` = `feat/process-command-experience-20260924` at `e24596543`: a portable CLI runner with no kernel change.
- Follow-on:
  - `docs/research/2026-10-04-ftl-lessons-brainstorm.md`: candidates on the shipped baseline.
  - `docs/research/2026-10-04-chio-kernel-north-star.md`: the kernel north star, eleven bets that fold these specs into a small, proven, fast and agent-safe kernel.

## Revision history

**Revision 4, adversarial review (2026-10-05).** Specs 9 and 10 were reviewed first, then specs 3, 5 and 8, the three that carry live defects. Each review read the spec against M:, V: and W: code and against its siblings. Every Blocker and Major was applied, and each spec records its dispositions in a `## Review disposition` table.
- **Spec 9 (machine)**, revision 3. Latches have three scopes. A new `NonDurable` class covers `Monetary` and development `Off` modes. Post-effect step and receipt-append events let the machine own the receipt decision. Driver-drop rules (M17), trailing hint groups (M18) and twelve theorems are added.
- **Spec 10 (crossing)**, revision 3. Commits fall into three classes, and only the first two anchor before acknowledgement. Stop dispositions are per crossing kind. A priority lane serves stop control. `KernelStopped` writes no tombstone. Sharding moves to a later phase with preconditions. D1 stays with spec 3.
- **Spec 3 (reservations)**, revision 4.
  - The obligation is a consuming `post_effect -> Discharged` region, minted at dispatch and discharged at the receipt commit point.
  - `BoundaryFailure` separates a rejected commit from an unconfirmed one.
  - A pre-dispatch drop compensates and never latches.
  - `LatchScope` is the single latch definition.
  - The spec states its division of labor with specs 9 and 10.
- **Spec 5 (events)**, revision 4. Split into Part A, the bug-fix lane (D3, D4, N14, N26, N27, N30), and Part B, the hint vocabulary, deferred until a second surface consumes hints on the wire. D3 now uses a per-request response slot, because retrying a request without `chioRequestId` would redispatch it.
- **Spec 8 (stop)**, revision 2. A host restarted during a stop now comes up `ready_stopped`; revision 1 refused to start. Heads are shared per store. A stop-intent latch makes a stop durable under overload. Asymmetric resume waits on an operator identity prerequisite. Phase 0 closes AC6.
- **Specs 1 and 4** take the cross-spec consequences: `ManageDelegationParent` is `deny` (matching M:), R5b grows to three ops, P5's stop point is the return-admission commit, and the drain uses the new latch names.
- **This overview** adds findings N26-N30 and cross-spec decisions 14-19, and updates the bug-fix lane.

**Revision 4a, Codex review round 1 (PR #1174).** The PR's automated reviewer raised 34 comments across all eleven specs. Each spec records them in a `Codex review (PR #1174, round 1)` disposition block. Notable fixes:
- spec 3 reserves post-effect evidence capacity before dispatch and stamps receipts at creation time;
- spec 4 fences ordinary output release at closure and backfills authority refs before fences;
- spec 5 adds H10 durable cursors for hints from outside sources;
- spec 6 binds results and responses to signed request identity;
- spec 8 adds a per-scope stop-intent journal, a signing obligation and shard freshness leases;
- spec 9 adds `ReleaseAuthorized` and total post-effect failure handling;
- spec 10 adds idempotent receipt moves and settlement that passes fences when its subject committed before the cut;
- spec 11 makes the integrity join idempotent.

**Revision 4b, Codex review round 2.** Six comments were fixed:
- spec 9 and spec 3 never compensate a dispatch commit that was submitted but not acknowledged;
- spec 9 records `Released` only on the `ReleaseHold` acknowledgement;
- calls under integrity tracking take the durable path, never the check-only or `NonDurable` path (spec 9 section 4.4, spec 10 X13 and X13c, spec 11 I4b);
- spec 11 observation ids are per delivery and destination context;
- integrity faults get their own `IntegrityFaultV1` block in spec 2's tagged classifier;
- spec 5 routes server requests by causal inbound identity.

**Revision 4c, independent Codex-agent review (2026-10-05).** A separate review at `a12c5ea35` (handoff in `arc-worktrees/ftl-lessons-specs-review-handoff.md`) raised 15 findings, all applied:
- spec 2: removes a recursive hash binding (Blocker);
- spec 11: the endorsement exception becomes part of the authoritative predicate; the bounded-return guarantee is stated precisely; separate allow and deny disclosure;
- spec 6: removes a kernel/fabric dependency cycle; adds a sealed submission record;
- spec 7: one confinement record per lane;
- spec 8: stop intents have identities;
- smaller fixes in specs 1, 4, 5 and 10 and the north star.

It also audited the defect table. 35 rows are confirmed. N20 and N21 above are qualified, and D5's citation is clarified.

**Revision 4d, independent review pass 2 (2026-10-05, head `faec88fcd`).** The second pass found no Blocker. It raised 11 findings, all applied:
- spec 11: action contracts survive attenuation independently of the integrity level; bootstrap input is joined before readiness (I7a);
- spec 6: retry identity excludes the lift timestamp; the binding covers the kernel-authenticated namespace and capability;
- spec 9 and spec 10:
  - rail releases need a per-hold key with idempotency or fencing;
  - `StoreUnavailable` is distinct from `Unavailable`, and retained members are re-fed by `StoreRecoveryDriver`;
  - a signed `IdentityDisposition` on every deny, which spec 6 and spec 8 consume. It was two-valued (`Reusable`, `Terminal`) in pass 2, and pass 3 added `Retained` for unresolved commits;
- spec 7: required lanes come from the run plan;
- spec 8: compensated slow-path stop denials are not retryable;
- the north star's hot-path summary is corrected.

The pass audited 40 defect rows: 37 confirmed, and 3 correctly reclassified as non-defects.

**Revision 4e, independent review pass 3 (2026-10-05, head `880261fc2`).** The third pass compared the specs with #1160, #1173 and #1170. It found 0 Blockers and raised 5 findings, all applied:
- `IdentityDisposition` gains `Retained` for unresolved commits (spec 9 M20, spec 3 section 4.11, spec 6 rule 10, spec 10 X22);
- spec 6's bound builder seals the complete governed D1 request;
- one total `CrossingOrder = (store_uuid, commit_sequence, member_ordinal)` (spec 10 X4, spec 8 S7, spec 11 I22a);
- GT1 is restated with current #1160 hosted evidence (N5, spec 1);
- the north star's read-path summary is corrected.

**Revision 4f, independent review pass 4 (2026-10-05, head `c98641ddd`).** It found 0 Blockers and raised 4 findings, all applied:
- spec 11 admits endorsements only through one `VerifiedEndorsementFactV1` adapter, and the automatic P3 claim is withdrawn (R-11-07);
- spec 11 freezes the LtHash16 commitment and adds a versioned migration contract over the P4 journal (R-11-08);
- spec 4 closure joins W1's qualified issuer and its one migration (R-4-03);
- spec 1 and spec 10 cover the P6 setup, maintenance and signed-policy surface and keep the setup gate as a participant precondition (R-1-03).

**Revision 4g, independent review pass 5 (2026-10-05, head `038e2e190`).** It found 0 Blockers and raised 4 Major findings and 1 Minor, plus 1 Major in its follow-up check of the fix, all applied through the existing owners, with no new manager or ledger:
- spec 9 separates delivery from money. A refusal after the effect decides delivery only. `ContractualZeroCharge` needs a zero amount or a verified contractual delivery denial under a reversible hold, and a positive-cost ordinary refusal keeps its return and hold in `Finalizing(DeliveryRefused)` until the payment owner's own successor settles it (M11a). Specs 3, 4 and 10 follow (R-9-03);
- the follow-up check found that this could strand a payment that had already settled. The decision now reads the journal's actual stage first: a `Final` payment is recognized at the terminal with no new settlement, an in-flight intent completes under its original identity, and only an `Open` hold is retained (R-9-05);
- spec 9 gives each payment successor its own phase. `MutuallyAgreedUnknown` stays on the unknown terminal (M7a), and `ContractualCaptureWaiver` resolves a known return's positive pending capture in `Finalizing` (M7b) (R-9-04);
- spec 2 extends W:'s exclusive origin claim with one bounded successor chain (section 6.10, rules O1-O8). A replacement continuation keeps the original's verified provenance, and denials without a retained native row get no remedy until a retained-denial profile exists. Spec 11 carries the prerequisite (R-2-02);
- spec 8 keeps every incident stopper on the anchored stop chain. Bypass proofs carry the subsumed contributors, an unread entry retires only through an anchored `Reconcile` record, and resume waits for it (S19, S19a, S25a). Spec 10 adds `Reconcile` to the priority lane (R-8-03);
- spec 5 removes the last restore exception and states the journal-write limit once (R-5-02).

**Revision 4h, independent review pass 6 and PR round 28 (2026-10-06, head `0118c31a6`).** Three Major findings, each also raised by a bot comment, and one Minor, all applied through the existing owners:
- spec 2 makes reservation allocation in `reserve_successor_ordinal` a stop-gated `deny` `RecoveryControl` branch, checked before any claim mutation (round 33 makes exact authenticated readback explicitly `allow`). It moves root supersession from the reservation to the stop-gated `CreateWorkflow`, so a stopped or failed creation never disables the root. Specs 8, 1 and 10 register it (R-2-03);
- spec 4's closure no longer waits for a rail and no longer drops an unresolved payment. `stranded_final.delivery_obligations` lists every `DeliveryRefused` payment not confirmed `Final` by readback, as `Open` or `InFlight` (including `ReconcileFailed`) with its original intent (R-4-04);
- spec 5 Part A restores standard resource subscriptions by URI with no client-visible id. A failed re-authorization durably terminalizes the session with `subscription_not_restored` before it can be served; reconnect receives the terminal-state response and the client initializes a new session. `resources/updated` and a read cannot signal subscription termination, because read and subscribe grants are independent. Negotiated ids and `SubscriptionEnded` stay in Part B, which extends the same record (R-5-03, corrected by R-5-04);
- spec 11 I20a applies native-origin eligibility to both recovery-backed integrity remedies, and spec 2 adds `origin_retained` to the `Integrity` fact (R-11-09).

The review's architecture judgment and recommended order are in section 9.

**Revision 4i, PR round 29 (2026-10-06, reviewed head `0dddc9aa3`).** Six unresolved comments covered five issues, corrected in the existing owners:

- spec 5 performs subscription restore without per-subscribe persistence, before the generation bump. A failure can therefore persist terminal epoch `g` over stored generation `g - 1`; no terminal-store rule is weakened (4190686691, 4190699721);
- spec 2 binds and persists the authenticated successor scope at reservation, checks it on every replay and at `CreateWorkflow`, and checks that scope's stop head before mutation. Specs 1 and 8 carry the binding into their entry-point rules (4190699723);
- this umbrella now describes the terminal-session subscription behavior (4190699724);
- spec 4's conformance invariant matches the normative closure predicate: every entry is terminal, delivery-refused or incident-bound. Open and in-flight refused payments remain recorded without forcing settlement (4190699727);
- spec 7 rejects mismatched worker attribution or launch evidence even on an ordinary call; unavailable evidence may still yield an unverified claim, subject to the existing mandatory-claim checks (4190699733).


**Revision 4j, PR round 30 (2026-10-06, reviewed head `f5ced410e`).** Four comments covered three issues:

- spec 2 adds `RetireSuccessorReservation` to the existing recovery command protocol, under predecessor-scope `Cancel` authority. It retires an exact uncreated reservation even if its destination is gone, preserving history, scope binding and the original continuation's eligibility. Creation races and lost acknowledgements use the same claim transaction and command replay. Specs 1, 8 and 10 register its command, stop and commit classifications (4197009035, 4197054899);
- spec 5 Part A now owns ongoing standard-subscription authorization, quiet expiry and the shared terminal-intent persistence helper (A30/A31). Live delivery, replay, resync, rotation and post-persist activation all check authority; failure ends the standard session. Part B extends those same owners with negotiated subjects and wire events (4197054908);
- A17 persists the new generation together with all staged negotiated-subscription transitions and rebased end-event ids. H5a uses that one signed record, and emitted ids exactly match its durable markers. A failed write containing a new end takes the journaled terminal path rather than restoring a stale live entry (4197054921).


**Revision 4k, PR round 31 (2026-10-06, reviewed head `efce5522c`).** Four comments tightened existing ownership and wire contracts:

- spec 2 no longer shares a reserved or open ordinal between distinct resolution attempts, including in the same scope. Only exact attempt/scope retries read back the original link; deliberate retirement precedes a replacement at a new ordinal (4197548040);
- predecessor-scope `InspectWorkflow` exposes the workflow revision and bounded successor chain in one authenticated snapshot. An operator with `Inspect` and `Cancel` can construct exact retirement even after the successor destination is removed; reservation readback also includes the chain revision (4197555183);
- specs 1 and 2 freeze the legacy seven-command schema and introduce recovery-command profile 1.1 with explicit request/result schemas, registry advertisement, protected deployment selection and a dual-profile migration through the existing command owner (4197555199);
- spec 5 defines one `TerminalReason` vocabulary, including `subscription_not_restored` and `subscription_authority_lost`. The same cause is authenticated by versioned native terminal records, retained in the shared journal and used by Part B's unsigned terminal hint. Part A adds no client notification (4197555214).


**Revision 4l, PR round 32 (2026-10-06, reviewed head `45f19d48a`).** Three comments corrected remaining cross-contract gaps:

- specs 1 and 8 require exhaustive stop coverage for both recovery-command profiles, with one disposition table, every wire profile/variant pair tested through the decoder and writer, and identical dispositions for shared kinds (4197876467);
- spec 5 keeps each resync cursor and follow-up in its consumer's attachment record. A later consumer starts at the catalog prefix, while emission remains bounded by one session-wide chunk budget. Round 33 additionally directs each synthetic pass only to its requesting consumer, without rebroadcast (4197876482);
- spec 10's check-only release now explicitly rechecks `KnowledgeIntegrity` against current release policy and committed state. Failed integrity withholds output with a signed reason and `retry: Never` guidance; round 33 clarifies that a refused check-only read retains a reusable identity; a policy or tracking change cannot reuse the dispatch-time decision to release (4197876499).


**Revision 3, recovery implementation.** Recovery P0-P5 exists as code in W:, and much of it was assumed rather than read in revision 2.
- **Spec 2 (faults)** now plugs in as a recovery planner fact. W: maps an unsatisfied capability fact to the terminal `BlockedByCapability`, and the new `Authority` remedy kind is the upcall tier for exactly that case. W: pins one capability per workflow, so a resolution runs as a linked `AuthorityContinuation` workflow. Because recovery refuses delegated control tokens, an operator-assigned actor drives it.
- **Spec 7 (isolation)** recognizes that P5 already cage-confines a zero-authority `confined_reader` child. It adds that profile, an exporter requirement (P5 emits no receipt), and an `output_channels` surface.
- **Spec 6 (adapter context)** moves state homes to P4 labeled model contexts. It makes lowering into a model a knowledge-joined release.
- **Spec 5 (events)** projects recovery hints from the implemented hash-chained recovery event log, adds the audience rule H9, and records the process ABI union as v4.
- **Spec 4 (teardown)** closes recovery workflows through `CancelWorkflow`, cites recovery's same-writer tombstone as the shipped fence, unifies three classifier copies, closes confined children, and adds a table of named release crossings.
- **Spec 1 (ABI)** pins L3 to the implemented recovery surface and grows L0 from 27 to 29 ops. It classifies the recovery, knowledge, semantic and confinement seams.
- **Spec 3 (reservations)** re-cites the implemented recovery reservations and adds two `Commitment` kinds.
- **This overview** reclassifies N7 and N8 and adds nine findings.
- **Spec 8 (durable stop epoch)** is added from brainstorm candidate 2, closing D2 (EV11/AC6). It yields findings N22-N24 and cross-spec edits: R5b in spec 1, open decision 5 resolved in spec 4, and `HintSubject::Stop` in spec 5.

**Revision 2, security, processes and verifiable work.** Every child spec was re-based on M:, V:, R: and P:.
- Spec 2 became a classification layer for the recovery lane.
- Spec 5 gained a single hint vocabulary.
- Spec 3 became an application of the unrepresentable-defects design.
- Spec 4 became the paper's missing closure rule.
- Spec 1 became a layered registry.
- Spec 7 reused `native_launch` and added worker confinement.

**Revision 4m, PR round 33 (2026-10-06, reviewed head `d851859a0`).** Ten unresolved comments are addressed through the existing session, admission, recovery and closure owners:

- spec 5 sends synthetic resync passes only to the consumer that requested them, with shared sequence/replay ownership, bounded transport slots and one fair session budget. Recovery traffic cannot create another consumer's broadcast lag. Its in-memory cursor covers the catalog/warning prefix as well as the URI suffix (4198048487, 4198110097);
- spec 10 maps a newly required output join on the no-write release path to typed `InsufficientIntegrity`, even if the current integrity level meets the floor (4198091675);
- specs 9, 10 and 3 keep all refused check-only reads `Reusable`: reason-specific `retry: Never` is guidance, not a durable tombstone or adapter binding (4198110084);
- specs 1, 2 and 8 classify reservation allocation and exact authenticated readback separately. New allocation rechecks active predecessor/original eligibility and absence of root or prior successor capture in its append transaction (4198091687, 4198091695);
- specs 4 and 10 check closure fences in the same writer transaction as every new operation insertion, before refs, reservations or approval parking can escape enumeration (4198091703);
- spec 4 replaces unbounded closure-artifact vectors with bounded evidence pages and a signed fixed manifest. Existing-owner snapshot revisions, counts, chained digests, publication CAS and migration inventory preserve complete evidence without materializing the entire ledger (4198110118);
- spec 5 separates the 32-bit event seed from native full-width persistence generations, reserves terminal counter/event headroom and covers the last legal seed (4198110108);
- Part B retains ended-subscription markers through flush and replay until authenticated explicit `chio/events/ack`, committed unsubscribe or session termination. Signed removal, unique subscription ids and rebase-before-reattachment preserve at-least-once ends without treating another stream's higher cursor as acknowledgement (4198110130).

These are specification changes and acceptance scenarios, not implemented or executed runtime tests.

## 1. Summary

FTL and Chio share a thesis: a small trusted mediator, with everything dialect-specific running as tenant code outside it.

The shipped baseline makes the analogy literal:

| FTL | Chio |
|---|---|
| System-call table | Six-op worker protocol |
| Handle space and its close | Capability subtree and terminal cancel |
| Poll with one-shot re-arm | Mailbox waits with one-shot re-arm |
| Reaper | `wait_children` |

The recovery implementation adds three more, each done more carefully than FTL does:

| FTL | Chio recovery |
|---|---|
| Container with no network handle | Zero-authority confined readers (P5) |
| Memory objects with mapping attributes | Labeled artifact versions with release after a knowledge join (P4) |
| Default-deny `ENOSYS` | Semantic coverage at the connector layer (P3) |

The most useful FTL lesson is a flaw: policy enforced in the same domain as the code it polices is advisory. Chio reproduces that flaw where a worker's credential sits next to untrusted workload code. P5 shows the remedy, and spec 7 generalizes it.

Across three revisions, each child spec narrowed to the gap that shipped and implemented work leaves open. The research also surfaced defects in that work itself (section 3).

## 2. Child specs (revision 4)

| # | Spec | Scope | Status |
|---|---|---|---|
| 1 | `2026-10-04-closed-kernel-abi-design.md`: layered kernel ABI registry and TCB budget | L0 `KernelOp` has 29 ops, adding `RecoveryControl` and `RecoveryDisclosureIssuance`, over 254 classified methods. The other layers are L1 `chio.process.abi.v4` (the union of two incompatible v3s), L2 `chio.work.v1`, and L3 recovery (7 `RecoveryCommandBodyV1` variants, 3 endpoints, 16 `RecoveryPermission`s, including P6's `Maintain`), plus component op enums. Rules R11-R13 and R5a (per-command stop dispositions). Recovery, knowledge, semantic and confinement seams are classified by polarity. Gates extend H11 and the trust-boundary census | PROPOSED (revision 3) |
| 2 | `2026-10-04-authority-faults-design.md`: authority fault classification for the recovery lane | A closed fault class and anti-oracle rules on the deny receipt, kept as audit evidence. The planner fact feeds a new `ExplanationRemedyKind::Authority` and assessment `RequiresAuthority`. Resolution runs as a linked `AuthorityContinuation` workflow (step 3a checks the predecessor's capability), with an operator-assigned actor and out-of-band delegators. `RecoveryContinuationBinding` is kept. It depends on generalizing the recovery profile and on extending W:'s origin claim with one bounded successor chain (section 6.10) | PROPOSED (revision 5) |
| 3 | `2026-10-04-typed-reservations-design.md`: post-effect discharge and typed reservations | Unrepresentable-defects Mechanisms A, C and D for every call that runs without durable admission, including `Monetary` and development `Off` modes. Phase 1 closes D1, N2, N28 and N29 on the legacy evaluator. The obligation is a consuming `post_effect -> Discharged` region bound to its request, and the discharge is minted at the receipt commit point. `BoundaryFailure` separates `RejectedBeforeCommit` from `CommitUnconfirmed`, and only the first compensates. A pre-dispatch drop compensates and never latches. `LatchScope` covers kernel evidence, a single operation and a session request. The ledger holds private-constructor tokens with a `retain` state. The Mechanism D gate is fully specified. Later phases follow spec 9's drivers (section 4.12) | PROPOSED (revision 4) |
| 4 | `2026-10-04-authority-space-teardown-design.md`: closing authority spaces | Uses the dispatch-commit fence (recovery's tombstone is the shipped instance) and one classifier unifying three copies. Closure covers five kinds plus recovery workflows (through `CancelWorkflow`) and confined children (through `NativeConfinedRuntime::cancel`). Adds a table of named release crossings, funded-work and knowledge invariants, stranded capacity, and the paper lemma | PROPOSED (revision 4) |
| 5 | `2026-10-04-unified-event-queue-design.md`: session event log and shared hint vocabulary | **Part A, bug-fix lane:**<br>- D3: a per-request response slot, a session-side `finish_call`, and an explicit outcome-unknown error. A retry is safe only with `chioRequestId`.<br>- D4: generation-seeded event ids with startup-safe persistence.<br>- Subscriptions persisted across restore (N26).<br>- The GET replay gap (N30).<br>- N14 redacted `inspect`.<br>- A confined-child-safe `cancel` count (N27).<br>**Part B, deferred** until a second surface consumes hints on the wire:<br>- `HintPort` with rules H1-H10; hint effects trail the commit.<br>- Recovery hints re-read through `read_recovery_workflow`.<br>- A process long-poll limited to `Lifecycle` and `Budget`. | PROPOSED (revision 4) |
| 6 | `2026-10-04-opaque-adapter-context-design.md`: lift-bound adapter correlation | The kernel cookie stays rejected. Under P4, the state home is the labeled `ModelContextV1` checkpoint, and lowering into a model is a knowledge-joined release. The verdict binding (`binding.v2`) carries the model-context digest. Semantic connectors are a non-goal Revision 4 adds trusted binding: both the tool result and the kernel response are checked against the receipt's signed request identity before lowering, and synthesized ids carry a per-payload `lift_id`. The independent review adds a signed `chio_fabric_binding` in receipt metadata, checked against a sealed submission record. It also adds a fabric-owned `BoundVerdictSource`, so the kernel never becomes a dependency of the fabric. Revision 5 drops the lift timestamp from the retry identity, binds the kernel-authenticated namespace and capability (`binding.v3`), and consumes the shared `IdentityDisposition`. | PROPOSED (revision 5, narrowed) |
| 7 | `2026-10-04-microkernel-isolation-backend-design.md`: confinement evidence for tool servers and workers | Tool confinement uses `native_launch`, and worker profiles are `direct`, `container`, `split_domain` and `confined_reader` (P5). Adds the `chio.confined-reader.evidence.v1` exporter, `output_channels` (reported, not gating), and `RuntimeAssuranceBacking` at the `Basic` tier. The microkernel backend stays EXPLORATORY, and FTL is NO-GO Revision 4 registers a `ChioConfinement` attestation verifier family. It also maps every confinement-covered receipt to exactly one record whatever the backend, and makes `worker_profile` a verified fact. Required lanes come from the agreement scope and run plan, not from receipt evidence. | PROPOSED (revision 5), sections 8-9 EXPLORATORY |
| 8 | `2026-10-04-durable-stop-epoch-design.md`: durable stop epoch | Replaces the process-local kill switch with a hash-chained `StopEpochV1` in the admission serving writer, scoped by kernel, tenant or recovery.<br>- **Startup.** Heads load before the startup sweep. A host restarted during a stop serves `ready_stopped`, and withheld output stays in durable custody.<br>- **Shared heads.** One set of heads per store serves every kernel in the host, including api-protect's proxy kernel.<br>- **Durability under load.** An fsynced stop-intent latch and a writer priority lane keep a stop durable under overload.<br>- **Dispositions.** Each crossing kind is `Deny`, `Withhold`, `Settle` or `AllowIfContainment`. `KernelStopped` is a temporary refusal that burns no request id.<br>- **Resume.** Asymmetric resume waits on an operator identity prerequisite and records `SharedCredential` until then. Stop authentication works without the clock.<br>- **Other.** Rules for restore and downgrade, and a process-host control socket.<br>- **Phasing.** Phase 0 closes AC6. Phase 1 closes EV11 | PROPOSED (revision 2) |
| 9 | `2026-10-04-pure-admission-machine-design.md`: pure admission machine (north-star bet 1) | One sans-IO `transition(&AdmissionState, AdmissionEvent) -> (AdmissionState, EffectList)` in `chio-kernel-core`, over one operation model: the union of the 19-state tool-dispatch and 15-state security models.<br>- The three classifiers become one cut function, which holds the single normative drain table that spec 4 cites.<br>- The 16 evaluators become one `evaluate` plus a blocking adapter.<br>- **Operation classes:** `Durable`, `ReadOnlyCheckOnly` and `NonDurable`.<br>- **Latch scopes:** `HaltOperation`, `LatchRequest` and `KernelEvidenceLatch`.<br>- Post-effect step and receipt-append events, driver-drop rules, trailing hint groups, and `KernelStopped` as a temporary refusal.<br>- **Proof:** Aeneas extraction to Lean with twelve theorems, a new `AdmissionMachine.tla`, differential tests against the legacy predicates, and DST.<br>- **Migration** starts with the startup classifier | PROPOSED (revision 4) |
| 10 | `2026-10-04-crossing-primitive-design.md`: crossing primitive and fused-commit hot path (north-star bet 2) | One `CrossingTx` with ordered checks for every crossing: stop epoch with per-kind dispositions, closure fence, revocation, knowledge integrity, reservations, and record.<br>- **Commit classes.** Crossing-authorizing and restrictive commits anchor before acknowledgement. Progress-only commits anchor within a bounded lag.<br>- **Side-effecting calls** take three commits: intent, return record and outcome.<br>- **Eligible read-only calls** outside durable coverage take a check-only dispatch plus a release write. D1's closure stays with spec 3 phase 1.<br>- **Refusals.** Unknown commit outcomes halt the operation and never compensate. Policy refusals on the fused path write a deny tombstone, except `KernelStopped`.<br>- **Writer.** Group commit with savepoints, and a priority lane for stop control. Sharding is a later phase with preconditions.<br>- **Targets:** 3 commits and at most 5 fsyncs per side-effecting call, a `read` median of 95 ms or less, and at least 4x throughput at 16 callers | PROPOSED (revision 3) |
| 11 | `2026-10-04-integrity-gated-admission-design.md`: integrity-gated admission (north-star bet 3) | `Constraint::RequiredIntegrity` over W:'s `ArtifactInfluenceV1` lattice, refined with origin classes and `ExternalBounded` for typed confined returns. A deny-only `IntegrityGuard` checks early, and the authoritative check runs inside spec 10's intent commit and check-only dispatch, using a new `knowledge_influence_heads` row. Every delivery records an output influence join. `InsufficientIntegrity` is a sibling fault kind in spec 2's tagged classifier, with its own `IntegrityFaultV1` block, with remedies through endorsement or a quarantined continuation. MCP edges start at unknown, so integrity-gated grants deny there Revision 2 makes the influence state a deduplicated observation set, so the join is idempotent set union. Revision 3 makes a verified exact endorsement part of the authoritative check (I15a). It states the guarantee precisely: unbounded or unknown influence cannot authorize a gated call except by endorsement, `BoundedExternal` is an explicit bounded allowance, and `BoundedSelection` adds an action-selection contract. Allow and deny receipts get separate disclosure rules. Revision 4 makes a requirement a pair: integrity level and action contract. Attenuation may raise the level but must keep the parent's contract. Bootstrap contributions are joined before a context is ready (I7a): pinning gives reproducibility, and trust needs an operator-signed `BootstrapTrustAssertionV1`. Revision 5 admits endorsements only through one `VerifiedEndorsementFactV1` (I15b), adapted from recovery approval or P3 evidence after every binding is checked. The automatic P3 claim is withdrawn. It also freezes the LtHash16 influence commitment and adds a versioned migration contract over the P4 journal (section 4.1). | PROPOSED (revision 5) |

## 3. Defects and findings

Items were verified on the M:/V: heads, or in W:'s working tree where marked.

### 3.1 Live defects

| ID | Defect | Status | Evidence | Where addressed |
|---|---|---|---|---|
| D1 | Non-durable calls can execute a tool and leave no receipt. The guard is disarmed before the receipt is built, signed and appended. Exposure includes mutating tools under `Monetary` and development `Off` modes, not only reads | Open | M:/V: `async_evaluation_core.rs:1740`; `nested_flow_evaluation.rs:1495`; M: `admission_operation/identity.rs:387` | Spec 3 phase 1 (bug-fix lane) |
| D2 | The emergency stop is process-local and resets on restart. It is unchecked by `issue_capability`, `issue_capability_with_security_context`, api-protect's sidecar mint routes, trust-control passport issuance, and governed active response | Open, ledgered as EV11 and AC6. AC6's remaining acceptance (document the in-process scope, verify the stop precedes fallible time reads) can close now | M: `kernel/construction.rs:369`, `:1674-1681`; `validation/issuance.rs:51`; `chio-api-protect/src/proxy/sidecar.rs:266`; `trust_control/passport_handlers.rs:1384` | Spec 8 phase 0 (AC6) and phase 1 (EV11). Spec 1 R5/R5a/R5b |
| D3 | When a hosted SSE consumer lags, the server warns and keeps going. A lagged initialize response at `:608` hangs the handler and strands the spawned session. A POST stream that holds the per-session request lock wedges every later POST, because the stream holds a sender and the channel never closes | Open | M:/V: `http_service.rs:517`, `:608`, `:702`, `:817`, `:860`; `:426` | Spec 5 Part A, section 4 |
| D4 | Restore reseeds event ids at 0 | Open | M:/V: `session_core/factory.rs:468`, `:684` | Spec 5 Part A, section 5 |
| D5 | The issuance freeze is never consulted with `Delegate` | Open | M:/V: `issuance_freeze.rs:1290` implements `Delegate` handling, but no production code constructs a `CapabilityIssuanceOperation::Delegate` query; only tests do. The cited line is the implementation anchor, not the missing caller | Active defense. Spec 2 covers remedies only |
| D6 | Overlay guards do not revalidate at dispatch | Open | M: `kernel/mod.rs:882` | Spec 4 section 4.2 |
| D7 | `ApprovalGuard` is unwired, with a stale doc reference | Open | M: `approval.rs:15` | HITL owners |
| D8 | Gemini adapter request ids collide | Open | M:/V: `chio-gemini-tools-adapter/src/adapter.rs:263` | Spec 6 rule 1 |
| D11 | Network and chain stacks sit in the kernel closure: `reqwest`, `hyper` and sigstore, alloy through `chio-settle` and `chio-core`, and in-crate `ureq` | Open | M: `chio-kernel/Cargo.toml:109` | Spec 1 R13 |
| D12 | There is no production `CausalLineageStore` | Open | M: `chio-security-types/src/ports/lineage.rs:294` | Spec 4 phase 4 |
| N1 | V:'s `chio-process/src/worker.rs` reverts M's authority-clock fix (`dcae5d7ba`) | Open (merge) | M:/V: `worker.rs` | Merge owners |
| N2 | The security recorder records `Released` before finalization | Open | M: `async_evaluation_core.rs:1727` | Spec 3 |
| N3 | Caged long-lived `AdaptedMcpServer` receipts carry no `native_launch` | Open | M: `chio-mcp-adapter/src/server.rs:141` | Spec 7 section 5.1 |
| N4 | The Mechanism D escape-hatch gate was never built | Open | M: `unrepresentable-defects-design.md:503-518` | Spec 3 builds it |
| N5 | GT1: at the M baseline the hardening gates did not run in hosted CI. At #1160 head `89e4641f6`, hosted job `111748798722` passed the structural, formal-traceability and temporal-security gate steps and then failed at workspace tests | Open (qualification) | M: `hardening-toolchain-spec.md:506-521`; GitHub Actions job `111748798722` | Rollout blocker until a whole hosted run passes |
| N6 | The default sidecar threshold collector lacks its production request-context source | Open | M: `threshold-approval-collection.md:282-283` | Approval owners |
| N9 | Container launch evidence is unsigned | Open | Spec 7 section 5.3 | Spec 7 |
| N10 | W2 plans HTTPS co-signing, while V: ships `IrohBilateralCoSigner` | Open | V: `lanes/bilateral.rs:795` | Work owners |
| N13 | Two incompatible `chio.process.abi.v3` definitions: M: `2a4c2fbe4` (broker routes) and W: (knowledge and recovery). A union must be v4 | Open (merge) | M: `chio-process/src/lib.rs:65`; W: `chio-process/src/lib.rs:54` | Spec 1 L1; spec 5 open decision 1 |
| N14 | With durable knowledge enforced, the worker `inspect` op always calls `storage()`, which refuses, so `inspect` fails for every enforced process | Open (W:) | W: `chio-process/src/worker.rs:156-162`; `lib.rs:282-288` | Spec 5 Part A, rule P6 bullets 1-2 (return the redacted snapshot) |
| N15 | New W: control-plane code samples `SystemTime::now()` instead of the authority clock. Same class as N1 | Open (W:) | W: `chio-control-plane/src/confinement.rs:53`, `semantic.rs:128`, `knowledge.rs:53` | Recovery owners |
| N16 | W:'s P5 edits `chio-cage` internals that M: moved into `chio-cage-plan` and `chio-cage-init`, and adds cage APIs that must be ported | Open (merge) | W: `chio-cage` diff (`launch.rs` +81) | Spec 7 open decisions |
| N17 | P5 confined-reader evidence lives only in review custody, with no receipt or attribution | Open (W:) | W: `docs/.../implementation/p5/OPERATIONS.md:46` | Spec 7 section 6.4 exporter |
| N18 | Doc-to-code drift in recovery: `RemedyOfferV1`, `recovery_deliveries`, cursors, `ExplainIntent`, adapter states and approval-withdrawing emergency revocation exist only in docs. V:'s W1 `WorkRecoveryLinkV1` routes to these names | Open | R:/W: `03-recovery-protocol.md:55`, `:114`; `08-protocol-operations.md:19`, `:57` | Recovery and work owners |
| N19 | The recovery profile is narrow: one template (`SupportTicketPublicIssue`) and one server, tool and purpose per process scope. V:'s work kernel assumes general recovery links | Design gap | W: `chio-security-types/src/recovery/commands.rs:12-14` | Spec 2 section 6.9 dependency |
| N20 | The drain classifier logic is duplicated. Startup reconciliation and recovery's original-operation closure classify separately today, and the proposed drain would add a third copy. The independent review notes there are two shipped classifiers, not three | Design gap | W: `kernel/admission_coordinator/recovery_runtime.rs:212-244` | Spec 4 (rule 5.6); spec 9's single cut function |
| N21 | The recovery P0-P6 implementation exists only as uncommitted changes in one worktree. An earlier estimate put it at about 117K lines, but no frozen diff manifest backs that count, so treat it as unverified | Risk | W: `docs/architecture/recoverable-agent-runtime/implementation/p5/FRESH-REVIEW.md:7`, `RULINGS.md:7`; W-only source | Repository owner (commit with a frozen diff manifest) |
| N22 | The kernel stop's HTTP handlers (`/emergency-stop`, `/emergency-resume`, `/emergency-status`) exist in `chio-http-core`, but no server mounts them. This is the concrete cause of EV11 | Open | M: `chio-http-core/src/routes.rs:33`; no non-test consumer of `handle_emergency_*` | Spec 8 S18 |
| N23 | The emergency handlers compare `X-Admin-Token` with `==`, not in constant time. This contradicts the sidecar control-credential precedent | Open | M: `chio-http-core/src/emergency.rs:193`; `docs/security/sidecar-control-authority.md:8-24` | Spec 8 S18 |
| N24 | W:'s `set_semantic_emergency_stop(scope, bool)` takes no actor, records no reason, authorizer or time, and has only a test caller | Open (W:) | W: `chio-store-sqlite/src/admission_operation_store/semantic.rs:369-386`; `chio-control-plane/src/recovery/tests/semantic.rs:513` | Spec 8 S5 (unify as the recovery scope behind an authenticated wrapper) |
| N25 | P4 records no influence join when tool output is delivered to a worker: `CapturedOutput` is defined but never constructed. A worker can absorb external data without its knowledge label rising, which defeats integrity gating. Separately, product reports and proposals are published with `externally_influenced: true, unknown: true` unconditionally, which over-taints (safe) | Open (W:) | W: `chio-security-types/src/knowledge/release.rs:59` (no construction outside definitions); `chio-store-sqlite/src/admission_operation_store/product/reports.rs:110-114`, `proposals.rs:86-90` | Spec 11 (output influence join on every delivery) |
| N26 | Restoring a hosted session silently drops its resource subscriptions. The resume record carries no subscription set, and the kernel drops `ResourceUpdated` for URIs the fresh session never subscribed to | Open | M: `chio-mcp-remote/src/remote_mcp/session_core.rs:264-281`; `chio-kernel/src/session.rs:1119-1123` | Spec 5 Part A (S5-04) |
| N27 | The worker `cancel` op returns the count of running descendants it cancelled. Confined children are spawned under the root, so the count reveals whether a confined child is still running, a bit P5 withholds | Open (W:) | W: `chio-process/src/store.rs:301-314`; `worker.rs:246`; `chio-control-plane/src/confinement.rs:118-145` | Spec 5 Part A (S5-21) |
| N28 | When a durable tool return cannot be recorded, the evaluator signs a `Deny` receipt (with ambiguous-dispatch metadata) for a call whose tool executed, then returns `Err`. Recovery later terminalizes the operation as `OutcomeUnknownAfterDispatch`, so one request has two contradictory terminal records | Open | M: `kernel/evaluation/async_evaluation_core.rs:1907-1932`; nested `nested_flow_evaluation.rs:1705` | Spec 3 phase 1, rule 25 (S3-21) |
| N29 | After execution, a `MustPrepay` capture failure calls `adapter.release` with the result discarded and signs a `Deny` for the executed call. A capture that is not `Settled` is also released with the result discarded, so a failed release leaves no record | Open | M: `kernel/validation.rs:1725-1748` | Spec 3 phase 1, rule 27 (S3-08) |
| N30 | GET replay snapshots the retained window before it subscribes to live events, so a notification published between the two is lost on reconnect | Open | M:/V: `chio-mcp-remote/src/remote_mcp/http_service.rs:829`, `:839` | Spec 5 Part A |

### 3.2 Resolved or reclassified

| ID | Finding | Resolution |
|---|---|---|
| D9 | Resume tag keyed with the signing seed | Fixed on the baseline (V: `session_resume.rs:802-824`) |
| D10 | A2A mapped `PendingApproval` to `Failed` | Fixed (M: `conversion.rs:99`) |
| N7 | Recovery capture does not recheck the denied capability | **Not a defect in W:.** The continuation must reuse the seed capability (W: `.../recovery/issuance.rs:76-81`), so ordinary revocation checks cover it. It applies only to spec 2's new `Authority` kind, where step 3a closes it |
| N8 | No constraint binds a capability to exact arguments | **Not a defect in W:,** because recovery never mints capabilities. It is a requirement for spec 2's `Authority` kind (`RecoveryContinuationBinding`). Its successor must also join W:'s exclusive origin claim (spec 2 section 6.10, R-2-02) |
| N11 | Stranded capacity has no closure path | Design gap, addressed by spec 4 section 8 (accounting, not reclamation) |
| N12 | Stale documents | Open: chio-process `ARCHITECTURE.md` mailbox list, `approval.rs` doc, the work kernel's stale #1160 checkpoint, and W0-W2 naming |
| | Confined-child status leak through `wait_children` or `inspect` (suspected) | **Verified not leaking** through `wait_children` (which refuses `confined_` ids) or `inspect` (which reports only the caller). Revision 4 found that `cancel` leaks it through its count (N27). Hosts other than the CLI runner must hold rule H9 (spec 5) |
| | `observe_recovery_source` has no actor check | Host-trusted query. Current control-plane callers authenticate the actor first (W: `chio-control-plane/src/recovery/runtime.rs:322-337`, `explanation/native.rs:80-93`). Spec 1 should classify it as a host-only query so a future caller cannot skip the check |

## 4. Corrections across revisions

1. FTL network access is not fully capability-gated: `NetCreate` and `ConsoleOpen` take no handle (spec 7 requirement Q1).
2. Chio's single-approver resume is library code that nothing in evaluation drives (D7).
3. Revision 1 duplicated designed work: a fault replay participant, a session-wide bus, a `confinement` receipt key, a closure-gate tool, and a governed closure effect.
4. Revision 2 relied on R: doc names that W: never implemented (N18), and asserted N7 and N8 as recovery defects. Revision 3 corrects both.

## 5. Cross-spec decisions

1. **One hint vocabulary, never authority.**
   - Spec 5's `HintSubject` and rules H1-H10 are the only notification semantics.
   - Recovery hints come from the recovery event chain.
   - Hints are audience-scoped (H9).
   - Spec 4 projects onto `Capability`, `Operation` and `Lifecycle`/`Terminal`.
2. **One remedy path.**
   - Every authority resolution flows through implemented recovery.
   - Spec 2 adds one planner fact, one remedy kind, one assessment and one linked-workflow template, and nothing parallel.
3. **A remedy dies with the denied capability.**
   - Spec 2 step 3a checks the predecessor seed's capability.
   - Spec 4 relies on it, and closes recovery workflows through `CancelWorkflow`.
4. **Reservation classes.**
   - Recovery call slots, provider lookups, grant issuance, D1 seals, F1 backing and process slots are `Commitment` entries with no compensator.
   - The machine's own releases are `PreDispatchNoEffect`, `TransportNotAccepted` and `ContractualZeroCharge` (spec 9 `MachineRelease`). The drain uses only the first two.
   - `ContractualZeroCharge` needs a zero recomputed amount or a verified contractual delivery denial under a reversible hold. A delivery refusal alone is never pricing authority, and it never re-decides a payment the journal already records: a settled capture, authorized release or resolved waiver stands, and an in-flight intent completes under its original identity. Only a refused return whose positive hold is still `Open` keeps it until the payment owner's own successor settles it (spec 9 M11a). Closure records every refused payment not confirmed `Final`, `Open` or `InFlight`, and never waits for a rail (spec 4 section 8).
   - After an unknown outcome, only `MutuallyAgreedUnknown` releases a hold (spec 9 M7a). `ContractualCaptureWaiver` resolves only a known return's positive pending capture in `Finalizing` (spec 9 M7b).
5. **Durability for work.** Every work profile requires durable admission.
6. **One escape-hatch gate.** It is the Mechanism D gate, and it includes W:'s `Drop`-quarantine sites.
7. **Reuse shipped gates.** H11 budgets and the trust-boundary census. GT1 blocks any claim.
8. **Confinement bindings.**
   - Tool confinement uses `native_launch`, or the backend-neutral `confinement_launch` for backends other than the Linux cage.
   - Worker confinement uses `worker_profile`, including `confined_reader` evidence exported from P5.
   - Verifiable work requires confinement through `RuntimeAssuranceBacking`.
9. **Correlation stays out of the kernel.**
   - `binding.v3` (spec 6) is the one authoritative binding version. It binds:
     - the kernel-authenticated request namespace;
     - the submitted capability id;
     - the invocation digest, which includes `provider_call_id` and excludes `received_at`;
     - the D1 permit and the P4 model context.
   - The kernel signs the binding as `chio_fabric_binding` and authenticates the namespace in the reserved `receipt_context`.
   - Under P4, lowering into a model is a release.
10. **Closure is manual and economically inert.** It never touches earned claims, sealed allocations, escrow deadlines, pins or knowledge, and it records stranded capacity.
11. **Name every crossing.** Dispatch commit, the recovery tombstone, P4 release and the P5 return-admission commit each declare their linearization point. The registry is spec 10 section 4.2 plus spec 4 section 4.3 (spec 10 X1; brainstorm candidate 9).
12. **Process ABI v4.** The union of M:'s and W:'s v3 definitions is v4. Spec 5's `inspect` fields ride it.
13. **Signed surface is additive.** The program adds only metadata, artifacts and closed-enum variants:
    - spec 2: the `authority_fault` block, `RecoveryContinuationBinding`, the `Authority` remedy kind, and the `AuthorityContinuation` template;
    - spec 3: `chio_runtime.post_effect_fault`;
    - spec 4: closure artifacts;
    - spec 8: `chio.stop-epoch.v1` and the `chio_runtime.stop` receipt block;
    - spec 7: `worker_profile` and the confined-reader evidence export.

    No receipt kind, verdict variant or native wire message changes.
14. **Three latch scopes** (spec 3 section 4.8):
    - `KernelEvidence` gates new dispatch until an unpersisted post-effect record flushes;
    - `Operation` halts one operation;
    - `SessionRequest` latches one request (spec 4).

    Spec 9 emits them as `KernelEvidenceLatch`, `HaltOperation` and `LatchRequest`. A revocation, closure or unknown commit never closes the whole kernel.
15. **Spec 9 decides, spec 10 executes, spec 3 binds.**
    - The machine chooses every transition and receipt decision.
    - `CrossingTx` executes commits and reports `Committed`, `Refused`, `OutcomeUnknown`, `Retry` or `StoreUnavailable`. `StoreUnavailable` covers retry exhaustion, a poisoned owner and a failed recovery fence, and spec 9 M19 retains the same planned member and its holds for it. `Refused(Unavailable)` means only that the fused form is ineligible (spec 10 section 4.1).
    - Spec 3 owns the affine contract that ties a dispatched effect to its discharge, plus the latch and the Mechanism D gate (spec 3 section 4.12).
16. **An unknown outcome never compensates.** None of these releases a hold or certifies non-execution: `CommitOutcomeUnknown`, `BoundaryFailure::CommitUnconfirmed`, or a receipt append whose outcome is unknown.
17. **Commit classes** (spec 10 section 5).
    - Crossing-authorizing and restrictive commits are acknowledged only after an anchor sync.
    - Progress-only commits anchor within a bounded lag.
    - Losing an unanchored commit to a restore can never enable a crossing its presence would have refused.
18. **Stop dispositions are per crossing kind** (spec 8 section 5): `Deny`, `Withhold`, `Settle` or `AllowIfContainment`.
    - `KernelStopped` is temporary: it writes no tombstone and burns no request id, except where a slow-path begin row already exists, as on M: today.
    - `StopHeads` are shared per store across every kernel in the host.
19. **Hints trail commits** (spec 5 Part B, spec 9 M18).
    - `HintPort` is infallible and best-effort.
    - Hint effects run in a trailing group only after the commit group's `Committed` acknowledgement.
    - H2 holds per commit class: a restore can undo a hinted progress-only change.

## 6. Sequencing

```text
protect the work first:
  N21      -> commit and push the W: recovery implementation to a branch (owner's decision)

bug-fix lane (needs no approval of the larger designs):
  N14, N27 -> spec 5 Part A process fixes (redacted inspect; cancel count excludes confined children)
  N15, N1  -> authority clock in W: control plane and in V:'s worker.rs
  D1, N2, N28, N29 -> spec 3 phase 1 (consuming obligation, BoundaryFailure split, latch scopes)
  D3, D4, N26, N30 -> spec 5 Part A transport hardening
  D6       -> spec 4 phase 1 overlay revalidation
  D8       -> spec 6 phase 1
  N3       -> spec 7 native_launch for adapted servers
  AC6      -> spec 8 phase 0 (document the in-process stop scope; test that the stop precedes fallible time reads)
  D2, N22, N23 -> spec 8 phase 1 (durable chain with stop-intent latch, heads before the startup sweep
                  and ready_stopped, heads shared per store, mounted routes plus process-host control
                  socket, constant-time credential, SharedCredential authorizer)

merge planning (M: + V: + W:):
  N13 process ABI v4; N16 cage crate port; N20 classifier unification; N18 doc-to-code names

gates (blocked on GT1 for any claim):
  spec 1 registry, census and budgets; Mechanism D gate (with spec 3)

after recovery generalizes beyond one template (N19):
  spec 2 Authority remedy; spec 5 recovery projections at scale; spec 4 workflow closure at scale

after W1/W2 land:
  spec 2 AllocationHolder and Payer templates; spec 4 work trigger; spec 5 work hints
  spec 4 phase 3 joins W1's qualified D1/S1 issuer and its one migration (spec 4 section 6.2 rule 6)
```

Review status:
- Adversarially reviewed in revision 4: specs 9 and 10, then specs 3, 5 and 8. Each spec's `## Review disposition` table records its findings.
- Suggested order for the rest:
  1. Spec 11, the third keystone, which carries N25.
  2. Spec 7, where P5 and the exporter apply.
  3. Spec 4.
  4. Spec 2.
  5. Spec 1.
  6. Spec 6.

## 7. Considered and rejected

| Idea | Rejected in | Reason |
|---|---|---|
| Kernel-carried opaque adapter cookie | Spec 6 | Edges are in-process, and P4 model contexts and operation keys already hold this state |
| Adopting FTL as an isolation backend now | Spec 7 section 8 | Ambient object creation, `lx` shares a domain with the workload, and there are no IPC, filesystem or quotas |
| Pre-reserving a receipt-log slot | Spec 3 | Moves the failure instead of removing it |
| A parallel fault replay participant or remedy path | Spec 2 | Recovery owns single use and continuations |
| Swapping capability inside one recovery workflow | Spec 2 revision 3 | W: pins one capability per workflow. A linked workflow keeps that invariant |
| A new authority obligation type in grant v2 | Spec 2 revision 3 | Keeps issuers separate from approvers. Authority evidence stays in the prerequisite step |
| Kernel-minted or standing fault resolutions | Spec 2 | The kernel is a verifier, not an issuer |
| A reserved mailbox channel for process control hints | Spec 5 | It is charged to the call budget, so a process with no budget left could never learn it was cancelled |
| A new `confinement` receipt key | Spec 7 | `native_launch` already binds tool launches |
| `output_channels` as a gating surface | Spec 7 revision 3 | No tool-lane cage could then be fully enforced. It is reported instead |
| `GovernedResponseEffect::CloseAuthoritySpace` | Spec 4 | Permanent revocation remains manual |
| Line-count TCB gates and a new closure-gate tool | Spec 1 | H11 budgets and op census measure attack surface; line counts don't |
| Live patching of running agents | Brainstorm | Conflicts with `PROCESS_ABI` pinning and determinism |

## 8. Follow-on brainstorm

`docs/research/2026-10-04-ftl-lessons-brainstorm.md`:

| Candidate | Status |
|---|---|
| 1. Split-domain workers | Folded into spec 7 section 6, alongside P5's `confined_reader` |
| 2. Durable stop epoch | Specced as spec 8 (`2026-10-04-durable-stop-epoch-design.md`) |
| 3. Process exit as an authority transition | Recommended as a small spec |
| 4. Closure lemma | Folded into spec 4 section 11 |
| 5. Constraint-enforcer registry | Fold into spec 1, or a small spec |
| 6. Revocation confirmation token | Fold into spec 4 |
| 7. Verifiers as reference monitors | Fold into spec 1 |
| 8. Cross-owner hints | Deferred |
| 9. Crossing-point registry | Shared rule for specs 1 and 4. Spec 4 already has the crossing table |

## 9. Architecture fit and implementation order

The fourth independent review (2026-10-05, head `c98641ddd`), confirmed by the fifth (head `038e2e190`), compared the program with #1160, #1173, #1170, W1-W4, recovery through P6, and the accepted decomposition and runtime boundaries. Its judgment, adopted here, is to keep the following and add no parallel engine:
- **One native admission machine.** Spec 9 is extracted from the existing coordinator and drives live, startup recovery and closure paths.
- **One qualified writer per authority store.** Spec 10's executor works inside the existing serving owner and global commit chain, and registers every new record in the integrity, snapshot and migration catalogs.
- **The existing recovery and work owners.** Remedies, approvals, custody, D1/S1/F1 issuance and P6 policy application stay with the owners already selected.

**Where each spec lands.** Every spec extends an existing or already-selected owner:

| Spec | Owner it extends |
|---|---|
| 1 | Layered inventory generated from landed symbols, including the P6 surface (R-1-03) |
| 2 | `chio-recovery` planner and the store recovery owner, including W:'s exclusive origin claim, which gains one bounded successor chain (R-2-02) |
| 3 | Existing hold, capture and reservation lifecycles, and the native payment journal's release authorities (R-9-03, R-9-04) |
| 4 | Revocation, session and process owners, plus W1's qualified D1/S1 issuer (R-4-03) |
| 5 | MCP session, approval store, recovery event chain and process journal |
| 6 | `chio-tool-call-fabric` and `provider_verdict` |
| 7 | Cage, process runner and appraisal families |
| 8 | Serving-owner lease, fence, chain and anchor; every incident stopper lives in that one chain (R-8-03) |
| 9 | Admission coordinator, reading the native payment journal and successor verifiers rather than deciding money (R-9-03, R-9-04) |
| 10 | `SqliteAuthorityStore` and `SqliteServingOwner` |
| 11 | P4 knowledge journal, P3 verification, P5 returns, recovery approval and P6 policy (R-11-07, R-11-08) |

**Avoid creating new owners.** None of these is needed:
- generic orchestrators;
- a universal cross-owner transaction;
- a second approval workflow, influence ledger or closure database;
- a policy-activation service;
- another sandbox supervisor or attestation verifier.

**Recommended order:**
1. Freeze the owner and source contract: the exact M/V/W union, process ABI, P6 inventory, supported profiles and public schemas. Keep the bug-fix lane (section 6) independent of the refactor.
2. Extract and share the deterministic rules (spec 9), following ADR-0022's rule of moving domain logic before persistence. Freeze the transition model only with delivery and money as separate facts and each payment successor in its own phase (spec 9 M7a, M7b, M11a).
3. Introduce the crossing executor inside the qualified foundation (spec 10). Preserve participant preconditions, including P6 setup gates. Establish recovery at every commit and acknowledgement cut before tuning batching.
4. Join closure with W1's issuer migration (spec 4): one issuer transaction owns the fence, and one authorized migration retains it.
5. Land one versioned influence model and the endorsement adapter (spec 11) before freezing the integrity schema.
6. Qualify the real composed paths, calling public owners. Cover:
   - P3 connector, then endorsement, then capture;
   - P4 old-state restore, then the new integrity head;
   - P5 return, then selector, then exactly one action;
   - a P6 policy change, then capture;
   - a W1 closed issuer, then migration, then a refused mutation;
   - protocol lift, then exact request, then a retained or terminal outcome.
7. Measure on one shared authority writer at concurrency 1 and 16, then extract stores incrementally under ADR-0022. The 95 ms median remains plausible but unmeasured, and the 4x throughput target is not yet established.
