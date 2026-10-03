# Verifiable Work Architecture Whitepaper Finalization Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax. Execute P.1 through P.4 before W1 through W4, as the owner requested. Execute P.5 when the integrated implementation evidence exists.

**Goal:** Complete a professional architecture paper centered on work as a reusable programming abstraction across independently governed systems.
**Architecture:** Present the completed design and common programming model first, then establish how existing Chio mechanisms realize it and which guarantees follow. Separate the architecture manuscript from statements about implementation, measurement and release.
**Tech Stack:** Existing LaTeX manuscript, bibliography, claim register, reproducibility tools and PDF pipeline.
**Spec:** [whitepaper design brief](../specs/2026-10-03-agentic-work-kernel-design.md#whitepaper-design-brief), the three component specifications linked there.
**Working source:** docs/papers/verifiable-work at 611660eb24521a4d02020615f650dadad92eae03. Preserve the approved title.

## Global Constraints

- Retain the title: Chio: A Peer-to-Peer Economy of Verifiable Work.
- Architecture sections describe the completed design in present tense.
- Do not invent observed results, outside participants, shipped surfaces or release acceptance.
- Preserve original theorem premises, proof scope, source pins and failed/partial evidence unless a separately reviewed technical change justifies an update.
- No em dashes. Avoid promotional superlatives, implementation-language framing in the abstract, and a concluding abstract sentence that is a limitation inventory.
- Apply all [parent constraints](../specs/2026-10-03-agentic-work-kernel-design.md#global-constraints).

## Review Focus

- Present-tense architecture is mistaken for completed empirical deployment: explicit manuscript type and evidence provenance, no invented shipping claims (P.1/P.4).
- Adapter breadth implies uniform enforcement or universal compatibility: actual support dimensions and clear kernel boundary (P.2/P.3).
- Recovery changes a sealed work commitment while claiming preserved identity: distinguish original work from an approved new continuation (P.3).
- A programming abstraction is described as another bearer token, globally atomic state or novel consensus: explain linked records, per-owner custody, partial failure and distinct authority lifetimes (P.2/P.3).
- Existing escrow equality is misrepresented as either exclusive novelty or architectural refutation: compare the common contract (P.3/P.4).
- Publication checker is weakened to turn old research gates green: explicit new profile, preserved legacy record and negative validation (P.1/P.5).

## P.1: Freeze the thesis and separate publication profiles

**Files:**

- Read: paper.tex, all sections, CLAIMS.json, PUBLICATION.json, ARTIFACT.md, ARCHITECTURE-REVIEW.md and sources.json.
- Create: docs/papers/verifiable-work/ARCHITECTURE-PUBLICATION.json and ARCHITECTURE-CLAIMS.json.
- Modify: docs/papers/verifiable-work/tools/check.py and tools/test_evidence.py only for explicit profile handling.
- Record: docs/papers/verifiable-work/FINALIZATION-REVIEW.md.

**Interfaces:**

- Legacy PUBLICATION.json and default --publication semantics remain preserved.
- New explicit --publication-profile architecture validates a separate schema: chio.paper.architecture-publication.v1.
- New profile tracks design_complete, implementation_claims_verified, artifact_consistent, technical_review_complete, empirical_claims_supported, publish_ready and source identities. Each Boolean has concrete acceptance and evidence references.
- Architecture-claims rows contain claim ID/text, kind (architectural, modeled, implemented, empirical), assumptions, spec/code/evidence references and current status. Planned APIs cannot be listed as implemented.

- [ ] Write the contribution statement and three precise contributions in the review record: common work abstraction; owner-controlled execution composition; reusable realization across existing protocol/host surfaces.
- [ ] Explain the deliberate change of publication question from proving a foundational/economic breakthrough to substantiating this architecture. Preserve the old open hypotheses and their evidence requirements.
- [ ] Add negative checker cases before changing profile handling:
      assert architecture_profile_with_unverified_implementation_is_rejected;
      assert missing_claim_evidence_is_rejected;
      assert legacy_open_gates_still_fail;
      assert unknown_profile_is_rejected;
  Implement these as ordinary Python unittest cases against the existing checker.

- [ ] Add explicit new-profile validation. A complete design draft can be accepted for internal review while publish_ready remains false; this is not a way to pass implementation claims.
- [ ] Preserve historical research evidence against its original source checkout. Adding planning/editorial files outside the paper currently affects the broad native source inventory; do not silently re-freeze old results against a changed inventory. Use a clean pinned evidence checkout or a separately reviewed historical-source validator with tests for changed native inputs.
- [ ] Commit: docs(paper): fix the architectural thesis and publication contract.

Acceptance: AW19/AW20. It is clear which artifact can be written now and what later evidence permits stronger claims.

## P.2: Write the abstract, introduction and programming model

**Files:**

- Modify: paper.tex, sections/01-problem.tex, sections/02-model.tex.
- Create: sections/03-programming.tex; update paper.tex section inclusion.
- Add the figure directly in the existing LaTeX/TikZ style.

**Interfaces:** Definitions used throughout: owner, agent, kernel, work commitment, program, admission, execution observation, release, funded obligation. Use the finalized architecture spec, not experimental module names, as the design source.

- [ ] Draft the abstract as one connected argument: independently owned resources; common execution contract; work commitment as composition unit; local admission and preserved commitments; architectural consequence. Target roughly 160 to 200 words, subject to clarity.
- [ ] End the abstract with what programs can do across independently governed systems. Put implementation language, local trial administration and detailed limitations in their appropriate later sections.
- [ ] Introduce a short programmer-facing work lifecycle before the encoding details: authorize an allowance, delegate/select, commit, execute, extend, inspect/recover, accept/collect. Distinguish owner setup from agent operations.
- [ ] Explain programmable sovereignty through capabilities, treaties, policy/guards and admission. Show owner-local kernels connected by work commitments/evidence, with untrusted planning outside each authority boundary.
- [ ] Give one pseudocode program and an API-review running example. Mark pseudocode as the architecture interface, not currently executable SDK syntax. Show how a second owner can refuse and how a planner can change without changing old work.
- [ ] Make the claims register point each architectural statement to a contract and each guarantee to its assumptions.
- [ ] Commit: docs(paper): lead with the work programming abstraction.

Acceptance: AW18. A systems reader can explain the abstraction and owner boundary before reading the preservation proposition.

## P.3: Reorganize the technical construction around that model

**Files:**

- Modify: sections/03-contract.tex, 04-execution.tex, 05-composition.tex, 07-related.tex, 08-limits.tex, 09-conclusion.tex.
- Update appendices 10-profile-details.tex and 11-evidence.tex only where the new organization needs exact cross-references.
- Preserve the source bibliography and add primary sources only when a new factual claim requires them.

**Interfaces:** W1/W2/W3 contract; recovery PR #1172 as the completed design assumption; existing proposition and proof as currently established mathematics.

- [ ] Describe how existing allocation, graph, capability, treaty, native execution and optional financial records jointly realize a work commitment. Avoid suggesting a universal new token or atomic transaction across owners.
- [ ] Explain the three different lifetimes of fresh permission, historical execution and earned obligations. Include current authority for output release and the distinct bilateral-delivery state.
- [ ] Integrate recovery as part of the architecture: exact new continuation after an approved change, unchanged original operation for historical settlement, unknown effect retained, and mediated artifact/child returns. Do not imply arbitrary rewrites of a sealed allocation.
- [ ] Explain protocol/host independence using the common kernel contract and explicit fidelity boundaries. Driver/adapter breadth supports the architecture without becoming a product feature catalogue.
- [ ] Re-read the preservation proposition against the broader narrative. Retain its additive-growth, honest-custodian and bounded-verifier premises. Add prose linking it to the programming model; do not quietly generalize its proof to all recovery/adapter behavior.
- [ ] Reframe related work as the architectural relationship to capabilities, workflow recovery, multi-agent task allocation, policy enforcement and settlement. Retain the factual financial overlap and acknowledge conventional constructions.
- [ ] Write the conclusion as the completed architectural result. It need not promise universal acceptance correctness, permissionless trust, Byzantine custody or economic superiority.
- [ ] Commit: docs(paper): connect sovereignty and preserved work through one execution model.

Acceptance: the technical argument explains how the abstraction works and its actual guarantees, without claiming that familiar components are impossible to compose elsewhere.

## P.4: Complete and review the architecture manuscript before implementation

**Files:**

- Modify: sections/06-evaluation.tex, README.md, ARTIFACT.md and the new architecture claim/profile records.
- Update: FINALIZATION-REVIEW.md.
- Rebuild: paper.pdf and the existing artifact manifest using truthful source boundaries.

**Interfaces:** Current source-qualified evidence remains current to its original revision; intended future W1/W2/W3 evaluation is specified separately and never inserted as a completed result.

- [ ] Separate architecture realization from evaluation. Describe the intended completed component organization; identify the currently evaluated D1/S1/F1 realization and its retained one-administrator evidence.
- [ ] Keep the existing empirical numbers only where their exact source and workload support the statement. A new service or SDK has no measured result until implemented.
- [ ] Put the new evaluation questions in the artifact/design companion during this early draft. Do not leave invented tables, empty results or repeated future-work paragraphs in the manuscript.
- [ ] Run make -C docs/papers/verifiable-work test and build, followed by the explicit artifact checks appropriate to the new profile. Verify every claim/evidence path and bibliography entry.
- [ ] Inspect the rendered PDF page by page for awkward breaks, diagram legibility, excessive notation, repetition and abstract/conclusion quality. Verify title, definitions, contribution claims and theorem scope against each other.
- [ ] Perform technical and prose review against the revised W1/W2 construction and second architecture review: client/service/native boundaries, qualified allocator ownership, exact request custody, original-ID resolution, independent observations and current release must agree. The reader must understand the programming abstraction, authority ownership, failure semantics, assumptions and evidence status. Resolve blocking findings; record the actual reviewer and method.
- [ ] Record architecture-manuscript completion separately from implementation and publication readiness; commit the final source/PDF pair.

Acceptance: a complete, professional manuscript of the intended architecture exists before W1 execution. It reads as a coherent kernel design; it does not claim the unbuilt product has shipped.

## P.5: Final evidence reconciliation and publication handoff

**Dependencies:** W4 candidate qualification, plus evidence for every empirical/implementation claim retained in the paper.
**Files:** sections/06-evaluation.tex, ARCHITECTURE-CLAIMS.json, ARCHITECTURE-PUBLICATION.json, ARTIFACT.md, sources.json, artifact manifest, paper.pdf and FINALIZATION-REVIEW.md.

- [ ] Replace the early implementation mapping with exact public runtime/owner-service/SDK paths and the integrated candidate's source identity.
- [ ] Add the two-application reuse results and matched comparison as actually observed. A tie, loss or unfinished outside trial remains visible in the relevant evidence and claim scope.
- [ ] Remove unsupported assertions or leave their claim status pending. Do not change historical PUBLICATION.json gates to passed merely because the architecture publication profile is ready.
- [ ] Rerun artifact/PDF checks and technical review after the final claim changes. Verify all publication-profile gates individually.
- [ ] Prepare the concrete source, PDF, reproducibility instructions and release-aligned claims for publication under the existing authorization process.

Acceptance: AW18/AW19/AW20. Publish-ready means the selected architectural claims are supported and the manuscript/artifact agree; it is not a certification of historical importance or proof of economic superiority.
