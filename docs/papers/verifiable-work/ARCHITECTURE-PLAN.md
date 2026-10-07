# Verifiable Work Architecture Revision Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this revision inline, followed by one fresh-context manuscript review.

**Goal:** Present Chio as a kernel architecture for peer-to-peer verifiable work, with a clear architectural argument supported by the existing protocol and evidence.

**Architecture:** Separate agent planning from the authority, execution history and obligations governing its effects. Explain how locally governed admission, treaties and linked work commitments support execution across owners; derive plan growth, recovery and payment from this model.

**Tech Stack:** Existing LaTeX manuscript, TikZ, BibTeX and Python artifact checks.

**Spec:** The user-approved architectural brainstorm, preserved in the design brief below. Execution was explicitly authorized on 2026-10-03.

## Approved design brief

Keep the title **Chio: A Peer-to-Peer Economy of Verifiable Work**. Lead with the kernel architecture and its execution model. Define what each kernel controls, where authority comes from, which records cross between owners and which state persists when a plan changes. Give programmable sovereignty, admission and treaties a central explanatory role. The specialist-payment example supports this argument. The abstract ends with the architectural consequence.

Work commitments link independently owned decisions about a particular invocation. They do not create a shared global authority or an atomic transaction across owners. Verifiable work has checkable authorization, an attributable execution history and acceptance under agreed rules. Keep the conditional preservation result, exact experiment, fair comparisons and trust assumptions intact.

## Global constraints

- Work only in `/tmp/chio-verifiable-work-paper`, branch `paper/verifiable-work-20261002`, starting at `f4a4c4db9fd13fb25dd6a89318e4725bf024b710`.
- Preserve native code, formal programs, experimental evidence, artifact tools and all existing research-gate statuses.
- Treat recovery as part of the architectural design, as previously instructed; distinguish specified semantics from the scope of measured implementation evidence.
- Reuse the existing delegation, swarm authority, treaty and recovery machinery. Introduce no replacement API or wire protocol.
- No em dashes. Use direct professional prose, define terms before relying on them, and avoid repeated claims of significance.
- No fabricated novelty, comparative advantage, universal verification, cross-owner atomicity, exactly-once external effects or independent deployment result.
- This is a manuscript revision. Existing artifact checks and semantic review are the relevant verification; no implementation-mirroring tests or native test campaign is required.

## Review focus

1. A new reader must understand the architectural contribution before encountering the local experiment.
2. Kernel scope, protected stores and authority selection must remain explicit; federation must not imply one global kernel or remote activation of trust roots.
3. Admission, execution evidence, acceptance and payment must remain distinct decisions with accurate lifetime rules.
4. Architecture prose and diagrams must not expand the preservation theorem, measured recovery cuts, information-flow guarantees or native qualification.
5. The signed receiver-mismatch example, stable continuation identity, separate financial backing and retained failure observations must survive the rewrite.

### Task 1: Rebuild the manuscript argument

**Files:** `docs/papers/verifiable-work/paper.tex`, `sections/01-problem.tex` through `sections/09-conclusion.tex`, and `README.md`.

**Interfaces:** Consumes the existing contracts, proof, source-qualified evidence and technical appendices. Produces an architecture-led manuscript without changing the technical profiles or experimental results.

- [x] Rewrite the abstract and introduction around the architectural problem and design principle.
- [x] Expand Section 2 into the kernel model, including local authority, durable state, cross-owner cooperation and an architectural diagram.
- [x] Connect commitments, execution and preservation to that model; explain the implementation as its realization and the experiment as supporting evidence.
- [x] Align related work, scope, conclusion and README with the final argument.
- [x] Run `make render` in the paper directory. Expected: exit zero, defined references and citations, no layout overflow after final inspection.

### Task 2: Review and package the revision

**Files:** `paper.pdf`, `ARCHITECTURE-REVIEW.md`, `PUBLICATION.json`, `artifact-manifest.json`, `PROGRESS.md`, and this plan.

**Interfaces:** Consumes Task 1's manuscript and unchanged evidence. Produces the rebuilt PDF and an accurate record of review and verification.

- [x] Obtain one fresh-context automated review of the complete revised manuscript against this brief and the technical sources. Repair supported findings, including prose defects within the user's publication-quality scope.
- [x] Run the existing `make test` artifact suite. Expected: all cases pass.
- [x] Inspect rendered pages and text; check links, claim paths, citations, warnings and unchanged native/evidence scope.
- [x] Update companion records without promoting research gates. Run `python3 tools/check.py --freeze`, then `make build`. Expected: passing artifact check and byte-identical rebuild.
- [x] Run `python3 tools/check.py --publication`. Expected: exit one for the existing four open gates and two false readiness flags, with no artifact failure.
- [x] Record the final PDF hash and verification results, mark this plan complete and commit the revision locally. Do not publish or merge.

## Completion record

The manuscript revision, fresh automated review, both minor repairs and final
artifact verification are complete. The 19-page PDF rebuilds byte-for-byte;
13 artifact tests pass, 658 artifact files agree, 28 claim records and 30 local
links resolve. The initial inventory failure and its plan-location repair are
recorded in ARCHITECTURE-REVIEW.md and PROGRESS.md. Existing research gates and
native qualification retain their prior scopes. The revision is committed on
the isolated paper branch without external publication or shared-branch integration.
