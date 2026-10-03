# Evolving Funded Work Implementation Plan

> Use superpowers:executing-plans for inline execution and one fresh whole-change review.

**Goal:** Execute the approved `docs/research/swarm-evolution/NEXT.md` through implementation, review and manuscript evidence.

**Spec:** `docs/superpowers/specs/2026-10-02-evolving-funded-work-design.md`

**Architecture:** Extend existing delegation guard layout and experimental native funded profile. Reuse runtime swarm/treaty verification, SQLite custody and the existing escrow rail.

## Global Constraints

- Preserve receiver-local authority and exact commitments. Fail closed.
- No parallel authority framework; use existing canonical types and signatures.
- Native admission and deposited backing are independent gates.
- Focus tests on changed boundaries, then run integration and relevant suites.
- Retain failed runs honestly; no em dashes; no unwrap or expect.
- User has authorized design, execution, review and paper updates. Keep this isolated branch for review; do not publish externally.

## Review Focus

- Stripping governed context or protected profile configuration must not downgrade admission.
- All D1/S1/F1 bindings must describe one receiver, capability, task, original request and allocation; avoid circular hashes.
- Growth cannot create another physical continuation owner or reassign funds.
- Recovery installs the same guards before touching original operations; earned payment does not require a fresh parent authorization.
- Fixture signing and local-chain evidence must not be represented as independent sovereignty or public finality.

## Task 1: Connect existing request and receiver admission boundaries

**Files:** `chio-kernel/src/delegated_work.rs`, its native tests; `examples/federated-work/src/funded_work/{native,agreement}.rs` and composed-profile support; example Cargo dependencies.

**Interfaces:** Produces an explicitly selected governed-context delegation layout and a protected opt-in funded admission configuration, installed before recovery. Existing funded agreement signs the full final request.

- [x] Add failing native tests for context-layout admission and substituted or absent permit, observing tool effects.
- [x] Implement the small layout adapter by reusing `verify_dispatch_permit` and the same output guard.
- [x] Add composed funded profile configuration and existing runtime hook activation; preserve legacy default behavior.
- [x] Verify focused native tests and compile the experimental executable. Expected: exact request admits; altered/missing bindings deny; legacy tests pass.
- [x] Commit implementation and record commands/results.

## Task 2: Execute growth, funding, failure and original-claim collection

**Files:** Existing funded-work example modules and new evolving-work scenario/fixtures; no new settlement contract.

**Interfaces:** Consumes Task 1 through the native executable and existing LocalChain/FundingRail/settlement lifecycle. Produces a retained JSON trajectory with exact binding and accounting evidence.

- [x] Write a failing end-to-end acceptance command/test covering the full trajectory and negative controls.
- [x] Build genuine signed swarm and treaty artifacts with existing constructors and verifier APIs.
- [x] Run first work, discover the second receiver from its result, seal and fund its exact invocation, install checked graph growth, then execute through receiver-owned admission.
- [x] Kill the intermediary after the child is payable and before parent completion. Recover and collect once with the original child authority.
- [x] Assert earlier work replay, physical claim identities, allocation/receiver/continuation attacks, exact effect counts and conserved token balances.
- [x] Run relevant Rust/rail regressions and Clippy. Expected: all acceptance assertions and existing affected tests pass. Commit.

## Task 3: Review, package the receiver trial and update the paper

**Files:** `docs/research/evolving-funded-work/`; whitepaper source, tools, evidence and publication records.

**Interfaces:** Consumes Task 2's retained trajectory. Produces reproducible local evidence, a concrete external receiver contract and matched-baseline trial package.

- [x] Retain current source hashes, commands, failures and terminal results with semantic trajectory checks.
- [x] Request one fresh-context whole-change review; fix material findings and rerun affected checks.
- [x] Update abstract and technical argument to the implemented unified execution. Keep sovereignty concrete and limitations localized.
- [x] Build/render/check the PDF and freeze artifacts. Expected: manuscript/artifact checks pass; actual outside-operator/economic publication gates remain explicitly open.
- [x] Commit final evidence and paper; verify clean worktree and report implemented result and next decisive tasks.

## Execution record

The user approved the prior next-task brief and requested execution with
Superpowers. This plan makes that authorization concrete; no repeated design
approval is needed. Baseline: `28e1ac92e7`.

Implementation and qualification tools: `d46524ee8c`. Tasks 1 and 2 share
one commit because the protected adapter and executable are one private compile
unit. Fresh review closed both Important findings. The 21-command campaign
and six opt-in chain regressions passed on the identical unchanged source
inventory; exact results live in `docs/research/evolving-funded-work/RESULTS.md`.

The frozen 19-page PDF rebuilds byte-for-byte. Manuscript, bibliography,
derived results, 28 claim records, edited links and artifact hashes agree.
The final evidence and paper commit completes Task 3; its delivery check is a
clean retained worktree. Publication validation intentionally exits one for
the four external gates and two false readiness flags. These research gates
are not part of the completed local implementation milestone.
