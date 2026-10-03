# Second architecture and implementation-plan review

Date: 2026-10-03.
Reviewed plan baseline: ab34047473844a045fc425f6d14aaa74cd71263e.
Method: coordinator source inspection, dependency/authority tracing and inline specification review. No independent reviewer or fresh native qualification is claimed.

## Judgment

The architectural thesis survives the review. Chio should expose a common work contract over its existing capability, treaty, guard, delegation, swarm, process and financial machinery. A new general-purpose engine would add a competing authority model.

The original plans were not precise enough to implement at the requested security and Rust quality standard. They left production ownership assumptions unenforced, mixed client and trusted host responsibilities, and specified several ambiguous data/error shapes. Eleven findings below are addressed in the revised specifications and tasks. These are planning corrections, not claims that corresponding production fixes have shipped.

The largest implementation obligation is qualified ownership of allocation and graph issuance. This is more substantial than adding facade methods. Existing rules and encodings stay; the serving authority must enforce the storage and issuance assumptions those rules rely on.

## Sources and scope

Source abbreviations below refer to exact commits in [SOURCES.json](SOURCES.json):

- Work: 611660eb24521a4d02020615f650dadad92eae03.
- Security: a99437b3ea8ef7ea03c7d2926049b27cb140b3c5.
- Recovery contract: de84fc306efbb4c8dd6de748d0ad2a8d695fd30e, PR #1172.

Work and security checkout heads were refreshed during this review and still matched these pins. The recovery implementation remains active on the owner's Mac; its accepted source/API landing is not visible here. That contract remains a dependency, not evidence of shipped code.

Priority P1 means resolve the design before implementing the affected boundary. P2 means a required API/quality correction in its owning task. Neither labels a newly demonstrated exploit in the active security candidate.

## Findings and corrections

### AR01 (P1): allocation persistence is an assumption, not a qualified serving boundary

Work, crates/platform/chio-workflow/src/delegation/store.rs:10 and :28: the store requires callers to prevent independent rollback, opens/creates SQLite tables and creates a namespace for an empty store. It has transactions and bounded accounting, but that is not the qualified serving lifecycle. Security, crates/platform/chio-store-sqlite/src/serving_owner.rs:294 and :327 supplies that separate owner/provisioning machinery; serving_owner/global_commit_chain.rs has a closed projection catalog.

Correction: W1.2 uses the existing serving connection, fence, integrity/continuity and migration contracts for production D1 state. Extract shared D1 rules rather than copy them. New records join projection, commit, snapshot and relocation inventories. Explicit import preserves original namespace/digests/permits and retires the old writer. Tests cover stale fences, copies, missing state and concurrent allowance consumption. A whole-domain rollback/Byzantine guarantee is not inferred.

### AR02 (P1): preparation must not publish competing signed graph successors

Work, crates/kernel/chio-swarm-authority/src/evolution.rs:11 explicitly requires a protected head. runtime-core/src/store/sqlite/swarm_authority_bundles.rs:88 implements CAS for one SQLite store. The original public Prepare Extend proposal returned authored material before the separately submitted head mutation; the plan did not specify how a losing candidate's signatures were withheld.

Correction: preparation returns an unsigned retained draft reference. The qualified graph issuer validates, commits and publishes the signed successor in that order, reusing the S1 verifier/record format. Runtime graph copies remain evidence lookup sources. W1.2/W1.3 test competing drafts, lost lease and no usable signed loser. Remote signing is supported only through an existing compatible durable issuance contract.

### AR03 (P1): retain-before-response is too late to establish issuer idempotency

Work, examples/federated-work/src/funded_work/composition.rs and evolving.rs use trusted local fixture composition. WorkerService's InvocationPreparer at worker.rs:56 is a composition hook, not proof that every new issuer has atomic original-ID readback. The proposed coordinator index could lose the interval between issuer commitment and recording its result.

Correction: W1.3 gives each issuer the immutable command/body/validity binding before publication. Owner-local readback survives coordinator loss; remote ambiguity keeps the original issuer ID. Tests lose the acknowledgement immediately after issuer commit and remove the coordinator projection. The command index is not an authority journal.

### AR04 (P1): a reusable commitment must not become a general credential container

Work, crates/kernel/chio-kernel/src/runtime.rs:62: ToolCallRequest contains capability, DPoP, execution nonce, approvals and declassification material. examples/federated-work/src/funded_work/agreement.rs:115 hashes the complete request. Recovery, 02-rust-design.md requires exhaustive request projection and distinct digest meanings; a native retained projection may deliberately omit one-shot credentials.

Correction: the public commitment carries a protected exact-invocation custody reference. W1.0 maps every request field and digest; W1.3/W2.3 use actual recovery custody and exact F1 preimages. No raw request in a clonable public view/index, no arbitrary URL/path dereference, and no substitution of a redacted native digest for the full-request digest. Preserve the acyclic signature assembly order.

### AR05 (P1): the agreement extraction still contains a dependency cycle

Work, examples/federated-work/src/funded_work/agreement.rs:53 embeds kernel::payment::SignedContractualCaptureWaiverTermsV1. chio-kernel already depends on chio-settle. Keeping only PaymentAdapter outside settle would not fix a wholesale move of this agreement type.

Correction: W2.3 moves chain/ABI/terms/observation/transaction code to settle. Full Agreement/SignedAgreement, native request verification and waiver integration stay in control-plane beside PaymentAdapter. No duplicated waiver DTO or Value escape hatch. Existing signature vectors and production dependency checks establish byte compatibility and an acyclic graph.

### AR06 (P1): query, financial reconciliation and result release need distinct contracts

The original Collect action and Option-based view obscured which authority was used. Recovery's ArtifactReleasePort/ConfinedReturnPort and KernelRecoveryPort::settle_retained have intentionally distinct authority lifetimes. Security's retained federation context also preserves original operation/request bindings rather than manufacturing a current authorization.

Correction: read-only WorkQuery includes original command/preparation IDs, so response loss can be resolved before a handle exists. Reconcile advances only existing obligations. Result bytes use current recovery release authority. W1.4/W2.4/W3.2 cover revocation during delivery, confidential topology/metadata, unknown effect and denied result reads. A status reference is not a data-release grant.

### AR07 (P2): the public host abstraction hides the real architecture

The original WorkRuntime forwarded prepare/apply/inspect to WorkHostPort. In practice, control-plane already owns composition; chio-runtime is an explicit facade and WorkerService already owns credential authentication (worker.rs:167). Another catch-all authority port would obscure construction and duplicate responsibilities.

Correction: a typed WorkClient uses a real local/remote transport boundary. Concrete WorkService modules compose existing authority ports. An internal WorkSession is constructed only by trusted authentication adapters. Pure code uses concrete types/static dispatch; traits are limited to actual deployment/transport boundaries. Reuse InvocationPreparer where it fits and add only the missing closed work operations.

### AR08 (P2): loose option bags and string fields permit invalid security states

The original result combined disposition with independent optional handle/view fields; views conflated not-applicable, pending and unavailable. Security's engineering-standard.md sections 2/3 require checked types, opaque verified values and distinct rejection reasons. Existing AdmissionDigest and UntrustedJsonText already provide reusable validation/decoding boundaries.

Correction: closed per-operation result and observation variants, checked semantic identifiers/digests, bounded constructors and private verified types. UnknownEffect remains native observation data. Preserve source errors privately and export distinct redacted rule codes. W1.1 includes compile-fail and shared wire vectors, including duplicate keys before Value conversion and aggregate allocation limits.

### AR09 (P2): seal replay and graph-history lookup need precise semantics

Work, delegation/store.rs:271 already retains/reuses a permit, but first calls claim_dispatch at :245, which checks liveness. Historical replay after expiry is different from live resealing. A crash can consume the claim before a permit exists. Also, swarm_authority_bundles.rs:156 intentionally falls back to the current bundle for an unknown historical graph hash; Some(bundle) alone is not proof of an exact history match.

Correction: keep live seal semantics; add authorized read-only retrieval of an existing historical permit. Never manufacture/backdate a missing expired permit. W1.4 resolves an earlier extension by exact retained candidate digest even after a later extension and verifies returned hashes rather than treating a nonempty lookup as success.

### AR10 (P2): async syntax does not provide bounded host execution

DelegationStore uses synchronous SQLite under a mutex. BilateralCoSigningProtocol at bilateral.rs:564 is synchronous. Recovery 02-rust-design.md already specifies bounded blocking execution, supervised ownership and no transaction across provider waits. The original tasks did not consistently make these execution requirements testable.

Correction: W1.0 fixes actual limits, W1.4 uses the existing bounded blocking path and tests blocked-peer isolation and cancellation at handoff. W2.1 tests saturation and disconnects. No unbounded spawn_blocking, detached recovery task or workflow-wide mutex. Native durable ownership survives a dropped client future.

### AR11 (P2): feature isolation and compatibility require measured boundaries

Work, crates/economy/chio-settle/Cargo.toml enables web3 by default and preserves a Rust 1.93 floor. A new work feature does not prove the preexisting graph is chain-free. The standalone example, worker SDKs and historical signed formats have separate build/compatibility boundaries.

Correction: record default/isolated/unified feature graphs in W1.0 and compare in W1.5/W2.3. Keep the full agreement outside settle, preserve MSRV/no_std contracts and historical bytes, and test installed SDK imports, old/new negotiation and lossless numeric encodings. W4 tests schema-compatible rollback or explicit refusal, never discarding unknown obligations.

## What remains intentionally unchanged

Capability validation, native guards/policy, treaty admission, D1 attenuation, S1 additive verification, process reservation, native capture, payment journal ownership and the recovery lane's decision/release logic remain the reused foundations. This review introduces no new cryptographic primitive, scheduler, consensus protocol or financial state machine.

The whitepaper plan still runs first as a completed-architecture specification. Its technical construction must reflect these owner/custody boundaries. Implementation/evaluation claims continue to require observed evidence. No additional novelty experiment or third showcase application is added.

## Acceptance and residual work

[The runtime plan](../../superpowers/plans/2026-10-03-work-runtime.md) now has separate reviewable boundaries for checked contracts, qualified issuance, preparation, original-operation recovery and public consumption. AW21 through AW25 make the new quality/security obligations traceable. W2/W3/W4 and the paper plan are aligned with those decisions.

This is an acceptable direction for implementation planning, with W1.0 required before freezing executable signatures and resource limits. Actual recovery API landing, semantic branch integration and the serving-store migration remain real implementation risks. Closing this review does not establish perfect code, complete security or beta readiness.

Document validation checks exact source pins, links, task/requirement coverage and change scope. Native tests in these plans are future acceptance work; none was run as a substitute for this review.

The second-pass validator passed: 13 Markdown files, five implementation/publication plans, 40 local links including seven anchors, 76 exact source hashes, and all 25 requirements mapped to 23 named tasks. Whitespace validation passed. The change set is limited to 14 planning/review documents; production source, Cargo files, the manuscript and its artifacts are unchanged.
