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

Pending: a separate, fresh-context automated reviewer will assess Task 1 against
the plan, source evidence and counterdesign buildability. This is not independent
human peer review or an external trial. The final record will include findings
and their disposition before Task 1 is marked complete.

## Scope decisions

The latest user instruction selects Task 1 and a proposal for successors.
Tasks 2 onward remain pending. The change consists of research documents and a
provenance/structure verifier; no Rust behavior changed, so a Rust workspace
build or runtime test would not validate this deliverable. The current paper and
the user's original and security/recovery checkouts remain outside the edits.
