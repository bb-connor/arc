# P5 final source review

Verdict: **With fixes.** One P1 and one P2 source finding remain. No P0 finding identified. Confidence is high in the two control-flow findings and moderate in overall source assurance. This report does not establish real Linux acceptance, hosted CI, deployment, or production qualification.

## Scope and method

This is the single fresh-context, read-only Superpowers final source review requested by the executor. I read the repository AGENTS.md, the Superpowers 6.4.1 code-reviewer instructions, P5 PLAN.md, the binding confined-returns specification, the ISO requirement/crosswalk material, the review package, the phase delta, and the review manifest. The review baseline is the retained P4 source archive plus the pinned pre-P5 cage inputs, not HEAD-to-HEAD. The implementation is uncommitted among inherited earlier-phase work.

The package identifies 74 authored inputs: 38 Rust/include sources and 36 other sources. I independently recomputed every listed file SHA-256 and found no mismatch against p5-review-package.json. Reviewed binding: `edfd4aed66f8f98c819a3f8e8d48c98cb6c52a41a6ffee87b8141d48ae9b065f`.

I read the complete new confinement contracts, host runtime, execution/channel modules, native boundary/context/launch/return modules, reader/canary implementations, and native/Linux acceptance tests. I followed their surrounding process lineage/cancellation/blob broker, signed capability registration/liveness, protected record mutation, native knowledge/influence joining, retention, cage preparation/exec/pidfd ownership, schema/vector/codegen and gate-package seams. Existing large modules were reviewed at the relevant complete functions and surrounding call paths; this is not a new audit of every inherited P0-P4 implementation or the entire cage.

No tests were executed by this reviewer and no source, index, branch, phase metadata, baseline, or gate log was modified. The executor's real Linux campaign was running separately. Findings below are source-supported and include deterministic regression recipes, not claims that those new regressions have been run.

## Strengths and code quality

- Native protected records own boundary identity, permanent request/capability/principal indexes, immutable input pins, state transitions and consumed child slots. Process attachment remains a separate, replayable journal operation and does not pretend to be a cross-store transaction.
- Cage preparation and observed exit are private-constructor custody types. Launch compares both the operator-pinned configuration and the later preparation/enforcement measurements. Sensitive stdin follows verified execution and a native child knowledge commit.
- The implementation independently recomputes the canonical Boolean projection. A well-typed result alone cannot authorize disclosure. Disclosure and endorsement use distinct signature domains and independently selected roots, with exact evidence binding and retained consumption.
- Channel buffers and packet parsing are finite; errors discard classified bodies; public debug implementations redact custody. The pidfd deadline does not depend on the caller promptly consuming the execution handle.
- Return admission and the parent knowledge join occur in one native mutation before sink I/O. The recording sink independently checks that its exact release already exists. Replays preserve the original release and authority identity.
- Separation between portable descriptors, native authority, process byte custody, and OS confinement is clear. The smaller modules make the critical state transitions and refusal paths inspectable without introducing another policy engine.

## Issues

### P1 / Important: parent cancellation can finish before return admission and still permit delivery

**Location:** `crates/platform/chio-control-plane/src/confinement.rs:209-232`, especially the one-time process check at lines 209-210 and unconditional sink call at line 232.

**Trigger:** A valid measured return has been staged and approved. `deliver()` validates the parent's process journal, then another thread completes `ProcessRuntime::cancel(parent)` before `admit_confined_return()` executes. The existing `BeforeAdmission` cutpoint at line 211 can reproduce this ordering deterministically by cancelling the parent and returning `Ok(())`.

**Source proof:** Process cancellation updates the separate process journal (`chio-process/src/store.rs:301`); it does not revoke the retained capability or change the native boundary. `admit_confined_return()` checks native state, capabilities, contract, evidence and recipient registration, but never checks the process journal. There is no later broker process check before `sink.deliver()`. Therefore the parent can already be cancelled when the native return is first admitted, and the sink still receives its Boolean bytes. The same stale process check also spans the potentially expensive native join, commit and sync.

**Impact:** This violates the P5 active-parent requirement and ISO-08 cancellation behavior. It is a disclosure ordering issue, not a request to retract data already delivered or undo an effect admitted before cancellation: in the specified reproduction, cancellation completes before the native admission starts.

**Fix direction:** Make cancellation and parent-return admission/delivery share a defined custody or serialization boundary. At minimum revalidate the actual parent process after native admission and immediately before release, retaining the committed admission if withheld. Do not treat the early broker lookup as durable permission. The full solution must explain the cancellation linearization point across the separate journals rather than hold a database transaction across arbitrary sink I/O.

**Regression:** Extend the real Linux useful-decision fixture. After staging and obtaining both signatures, install a `BeforeAdmission` observer that calls `process.cancel("root")` and returns success. Assert `deliver()` refuses and the sink stays empty. Also exercise cancellation after the parent join but before the first sink byte, retaining the existing admission and consumed evidence while withholding delivery. Existing cutpoint tests return an injected error immediately; they do not cover a successful cancellation followed by resumed delivery.

**Confidence:** High. No timing assumption is required with the existing cutpoint.

### P2 / Important: the confined resolver lowers the supported depth of ordinary process trees

**Location:** `crates/platform/chio-store-sqlite/src/admission_operation_store/knowledge/confinement/context.rs:108-109`.

**Trigger:** An ordinary process tree, with no confined capability or boundary anywhere in its ancestry, reaches 33 lineage entries (root plus 32 descendants). The configured process depth and kernel delegation limit allow that tree.

**Source proof:** The new resolver returns an error for any lineage longer than 32 before attempting to find a confined-capability index. Both `ProcessRuntime::recovery_security_context()` (`recovery.rs:55-60`) and ordinary invocation (`lib.rs:448-451`) now call this resolver unconditionally. Existing `ProcessLimits::validate()` permits depth 64 (`types.rs:56`), and the process lineage reader permits 65 entries (`store.rs:112-128`). Kernel maximum delegation depth is configurable. A supported ordinary context that previously resolved from its root now fails with `confined context unavailable`, even when confinement has never been installed.

**Impact:** P5 introduces a functional regression into ordinary child work beyond depth 31. It contradicts ISO-01's preservation of ordinary child semantics and the plan's confinement-specific bounded profile. It is fail-closed, so this is availability/compatibility rather than a security bypass.

**Fix direction:** Preserve the existing bounded ordinary lineage capacity (65 entries), and enforce any tighter confined limit only after identifying a confined boundary. Do not simply return `None` for overlong input, which could bypass detection of a retained confined ancestor.

**Regression:** Build an ordinary signed root plus 32 descendants under a SQLite-backed runtime with sufficient process/delegation ceilings and no confinement installation. Verify the leaf resolves the root's lineage and epoch, and ordinary invocation reaches its normal admission path. Retain tests proving oversized or invalid confined ancestry cannot fall back to ordinary context.

**Confidence:** High in the deterministic context-resolution regression. The ordinary invocation consequence additionally assumes the independently configured kernel delegation ceiling permits this depth.

## Plan alignment

P5-01 through P5-05 are substantially present within the deliberately narrow Boolean-only, no-provider, no-network, no-tools profile. The code provides host-issued boundaries, seed/parent joins, measured launch, bounded classified capture, exact independent authorities, commit-before-bytes and permanent replay/accounting. The P1 finding prevents closure of cancellation/active-parent behavior; the P2 finding prevents claiming unchanged ordinary-process behavior. P5-06 remains subject to the executor's real Linux evidence and final package resealing after any changes.

The selected profile's refusal to relaunch uncertain children and its permanent retention are coherent conservative choices. No expansion to arbitrary models, transformations, callbacks or streaming is required to close this phase.

## Testing assessment and recommendations

The source tests cover real native reservations, forged/substituted capabilities and artifacts, permanent counts and pins, lost acknowledgements, independent authorities, classified alternate channels, exact release identity, and a held-handle deadline. The Linux tests require measured executables rather than synthesizing enforcement evidence. The gate tooling distinguishes cross-compilation from real Linux execution and checks test/image inventories and source bindings. Portable schemas and shared fixtures are descriptive; their acceptance does not replace native semantic validation or signature/root selection.

Apply one test-first fix pass for the two findings. Re-run affected native/Linux and ordinary-process gates, then regenerate and reseal exact-source evidence. No broad style refactor is needed. Approval of the final phase requires the real Linux campaign and the repaired-source evidence, independently of this source verdict.

## Declined to judge

- Real Linux runtime success, including the final canary/deadline outcomes: the executor owns an ongoing independent Linux campaign; this reviewer did not run or validate its final results.
- Temporary missing/stale phase seals or logs while evidence is being regenerated: explicitly identified as an in-progress execution state, not a source defect.
- Hosted CI, deployment and production operation: outside P5 source review and no live evidence inspected.
- Provider conversation/cache reuse, tool invocation, broker egress and model budgets: disabled by the selected profile; enabling them requires another reviewed profile.
- Arbitrary schemas/projections, non-Boolean returns, status/error disclosure, per-chunk streaming and callback/mailbox delivery: intentionally unavailable, with no raw fallback in this profile.
- Nested confined-reader creation or automatic replacement launches after uncertainty: the implementation deliberately supports root-attached children and one measured launch per logical child.
- Exactly-once recipient-side side effects: replay retains an exact stable release intent, while sink effects/acknowledgements remain a separate host integration contract.
- Microarchitectural timing/covert-channel resistance and malicious trusted-host implementations of the broker/sink/operator installation ports: outside the stated trusted-host/profile boundary; this review checks the declared byte channels and production broker integration.
- Comprehensive Unicode/semantic equivalence between every generated SDK model and native validators: the schema/vector paths were inspected, but no exhaustive cross-language campaign was run; native authorization remains mandatory.
- Unrelated P0-P4 findings, inherited crate-wide style, and a fresh end-to-end audit of the pre-existing cage: outside the pinned P5 delta, except where inspected to establish the new behavior.

## Assessment

**Ready to merge or close P5? With fixes, and only after real Linux acceptance on the repaired sources.** The core design has substantive fail-closed ownership and mediation, but the parent cancellation gap is a release-authority defect and the unconditional 32-entry bound regresses ordinary process behavior. No source-only verdict can substitute for the still-separate Linux gate.
