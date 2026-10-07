# Task 1 acceptance and verification

Scope: the research package at G0. The task requires strong counterdesigns and a
precise consequential question; it explicitly requires no implementation. Source
inspection, a construction walkthrough and structural validation do not prove
equivalence, novelty or production correctness.

## Acceptance checklist

| Required output | Evidence |
| --- | --- |
| Full claim-relevant protocol/premise reading | [Source audit](task1-source-audit.md) and [source pins](task1-sources.json); older distributed IFC and partial-observation work added when the claim required them |
| Recovery mapping without duplicating implementation | [Crosswalk](recovery-crosswalk.md): all 111 requirements in 15 disjoint groups, with owning effort and future fixture seams; J1-J5 kept separate |
| Strong B1/B2/B3 | [Counterdesigns](counterdesigns.md): matched trust/resources, records, local transactions, cross-store attachment, host/label handling, E1/E2, cancellation and reusable baseline improvements |
| Complete worked example | Counterdesigns section 5 traces paid specialist, all-owner exact publication, lost ACK, E1/E2 outcomes, cancellation and authorized sibling work for every design |
| Falsifiable R1/R2/R3 | [Claim register](claim-register.json): all requested fields, assumptions, requirements, closest prior art, observable differences, falsifiers and next tests; unknown behavior explicit |
| G0 decision | [Decision](G0-DECISION.md): unsupported headlines rejected; one primary systems question retained; G1-G4 and manuscript re-entry remain open |

## Reproducible structural/provenance checks

Run from the repository worktree:

```bash
python3 docs/research/kernel-work/verify_task1.py
```

This checks the 16 pinned recovery documents against their Git blobs, the exact
111-ID inventory, crosswalk/register agreement, claim fields and evidence state,
immutable software URLs, local document links, formatting and the frozen paper
tree. The pinned recovery Git object must be available; if missing, fetch the
PR's history and retain the recorded revision rather than replacing the pin.

For this execution, downloaded primary sources are also available in the local
ignored plan workspace. The full provenance command is:

```bash
python3 docs/research/kernel-work/verify_task1.py --source-cache .superpowers/sdd/2026-10-02-kernel-breakthrough-research/sources
```

That additionally hashes all 29 cached primary documents. On another checkout,
retrieve the exact URLs into their manifest `cache_path` locations, then use
`--source-cache` with that directory. The command without the cache explicitly
reports zero primary-document hashes verified. Neither mode verifies scientific
arguments automatically.

## Fresh review

Reviewer: fresh-context automated `kernel_task1_review`, GPT-6 Astra, reviewing
`98b3bd2459c9b5421f0122f2eb1cf536412921d9` through
`3a2693a38eb804afcc6442488af8fa4cd656db68`. The reviewer ran the cache-backed
verifier, inspected the committed diff, and checked selected primary sources.

**Verdict: Task 1 accepted.** No critical or important findings; two minor
clarifications were identified. The reviewer judged that a competent engineer
could construct a strong conventional alternative and identify the claim's
falsifiers. This is automated acceptance, not independent human scientific
validation.

The executor treated the two clarifications as important specification
corrections for the final buildable description, because literal implementation
of the ambiguous boundaries could block earned settlement or expose protected
information. Both were resolved in one documentation pass:

1. **OPS-13 separation:** internal settlement uses narrow current recovery
   authority and historical evidence. External lookup and result release have
   their own current authority checks. Revoked result-read access cannot itself
   block authorized internal settlement.
2. **C11 financial observations:** payment occurrence, amount, beneficiary,
   exposed timing and acceptance-token existence require authorization for
   their actual observers, including S/V and public-ledger observers as
   applicable. A hiding commitment alone is insufficient. The positive scenario
   now states its metadata permissions; every design receives the same profile.

Verification of these prose corrections used the normative OPS-13 authority
table and C11/SEC-09 channel rule, plus manual walkthroughs of revoked-read
settlement and unauthorized public payment facts. These are specification
checks, not executed Task 2 fixtures. The full artifact/provenance check was
rerun after the edits. No second automated review or new runtime result is
claimed. No review finding remains deferred.

The review explicitly left implementation/deployment status under the user's
shipped assumption, equivalence/proofs/novelty to Tasks 2-4, native/performance
evidence to later experiments, and external validation/publication open. The
executor retains all those boundaries. The review's pending-record/checkbox
administrative items were finalized after its verdict.

## Observed checks

- Cache-backed verification passed: 16 recovery document hashes, 111 normative
  requirements, 15 disjoint crosswalk groups, three hypothesis records, and 29
  primary-document hashes. Local links and frozen paper checks passed.
- The documented no-cache invocation passed and explicitly reported zero
  primary-document hashes verified, as intended.
- A temporary copy with a deliberately corrupted S07 PDF was rejected at the
  expected source-hash check. Original cached sources were left unchanged.
- Committed and working diff whitespace checks passed. The source paper subtree
  remained `b8c5b771ca04903e219f9b42a50a050d326ba0ac`.

## Scope decisions

The latest user instruction selects Task 1 and a proposal for successors.
Tasks 2 onward remain pending. The change consists of research documents and a
provenance/structure verifier; no Rust behavior changed, so a Rust workspace
build or runtime test would not validate this deliverable. The current paper and
the user's original and security/recovery checkouts remain outside the edits.
The review and validation cover Task 1; later tasks remain unfinished. Keeping
this worktree and its ignored plan/source cache supports the subsequent research.
